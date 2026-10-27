// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! One output buffer of the NTFS change journal: the bytes `FSCTL_READ_USN_JOURNAL` returns
//! (ADR 0047).
//!
//! A buffer is the USN to start the next read from, eight bytes, followed by records "aligned on
//! 64-bit boundaries from the start of the buffer". The layouts are Microsoft's `USN_RECORD_V2` and
//! `USN_RECORD_V3`. Of each record this module keeps four things: its major version, the reference
//! number of the folder it is in, when it was written and why.
//!
//! **[`parse_buffer`] never reads a file name.** The journal names every file changed on the volume
//! while it retains, and nothing downstream needs a name (ADR 0047, "The privacy problem"). Neither is
//! the record's own file reference number or its USN kept: both identify one file on one machine across
//! two reports, which is what ADR 0021 declined to emit.
//!
//! [`match_buffer`] is the one exception, and it amends ADR 0047 Question 3 (ADR 0086). It reads a
//! name only to compare it with a name the caller already holds, and it returns no name, USN or file
//! reference: a match is a target index, a change kind and a time.
//!
//! A version 4 record carries extents and no time or name, and is only written when range tracking is
//! on; it is counted and skipped. A major version this module does not know stops the buffer, because
//! Microsoft says code that detects one "should not work with the change journal".
//!
//! A damaged record keeps the records before it: they come back with the error in
//! [`UsnBuffer::damage`], the way [`crate::pca::PcaFile`] keeps the lines that parsed (ADR 0013).
//! Nothing after a damaged record is read, because a record's length is the only way to find the
//! next one.

use jiff::Timestamp;

use crate::error::ParseError;
use crate::filetime;

/// Bytes before the first record: the USN to start the next read from.
pub const HEADER_LEN: usize = 8;
/// `RecordLength` and the two version numbers: what every record version begins with.
const RECORD_HEADER_LEN: usize = 8;
/// A version 2 record up to the end of `FileNameOffset`.
const V2_FIXED_LEN: usize = 60;
/// A version 3 record up to the end of `FileNameOffset`.
const V3_FIXED_LEN: usize = 76;
/// A version 2 record's `FileNameLength`, a `u16`.
const V2_NAME_LENGTH_AT: usize = 56;
/// A version 2 record's `FileNameOffset`, a `u16`.
const V2_NAME_OFFSET_AT: usize = 58;
/// A version 3 record's `FileNameLength`, a `u16`.
const V3_NAME_LENGTH_AT: usize = 72;
/// A version 3 record's `FileNameOffset`, a `u16`.
const V3_NAME_OFFSET_AT: usize = 74;
/// Records are aligned on this many bytes from the start of the buffer.
const ALIGNMENT: usize = 8;

/// `USN_REASON_DATA_OVERWRITE`: "The data in the file or directory is overwritten."
pub const REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
/// `USN_REASON_DATA_EXTEND`: "The file or directory is extended (added to)."
pub const REASON_DATA_EXTEND: u32 = 0x0000_0002;
/// `USN_REASON_DATA_TRUNCATION`: "The file or directory is truncated."
pub const REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
/// `USN_REASON_FILE_CREATE`: "The file or directory is created for the first time."
pub const REASON_FILE_CREATE: u32 = 0x0000_0100;
/// `USN_REASON_FILE_DELETE`: "The file or directory is deleted."
pub const REASON_FILE_DELETE: u32 = 0x0000_0200;
/// `USN_REASON_RENAME_OLD_NAME`: the record carries the previous name.
pub const REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
/// `USN_REASON_RENAME_NEW_NAME`: the record carries the new name.
pub const REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
/// `USN_REASON_BASIC_INFO_CHANGE`: attributes or time stamps changed.
pub const REASON_BASIC_INFO_CHANGE: u32 = 0x0000_8000;
/// `USN_REASON_CLOSE`: "The file or directory is closed."
pub const REASON_CLOSE: u32 = 0x8000_0000;

/// Where a record's file is, as the record names its parent folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentReference {
    /// A version 2 record's 64-bit `ParentFileReferenceNumber`.
    Index64(u64),
    /// A version 3 record's 128-bit `ParentFileReferenceNumber`, as its sixteen bytes.
    Id128([u8; 16]),
}

/// One change journal record, without its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnRecord {
    /// 2 or 3; a version 4 record is never returned, only counted.
    pub major_version: u16,
    /// The folder the file is in.
    pub parent: ParentReference,
    /// `TimeStamp`, "the standard UTC time stamp (FILETIME) of this record". `None` when the value is
    /// outside what a timestamp can hold; the record is still counted.
    pub written: Option<Timestamp>,
    /// `Reason`: the `REASON_*` flags accumulated in this record.
    pub reason: u32,
}

/// One output buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnBuffer {
    /// The USN the buffer says to start the next read from.
    pub next_usn: i64,
    /// The version 2 and version 3 records, in buffer order, up to the first damaged one.
    pub records: Vec<UsnRecord>,
    /// How many version 4 records were skipped.
    pub skipped_version_4: usize,
    /// Why reading stopped before the end of the buffer, when it did.
    pub damage: Option<ParseError>,
}

/// Parses one `FSCTL_READ_USN_JOURNAL` output buffer.
///
/// # Errors
///
/// [`ParseError::Truncated`] when the buffer is shorter than the eight-byte USN every buffer begins
/// with. Every other defect is reported in [`UsnBuffer::damage`] with the records before it kept.
pub fn parse_buffer(bytes: &[u8]) -> Result<UsnBuffer, ParseError> {
    let mut parsed = UsnBuffer {
        next_usn: header_usn(bytes)?,
        records: Vec::new(),
        skipped_version_4: 0,
        damage: None,
    };
    let damage = walk(bytes, |_, step| {
        match step {
            Step::Record(record) => parsed.records.push(record),
            Step::SkippedVersion4 => parsed.skipped_version_4 += 1,
        }
        Ok(())
    });
    parsed.damage = damage;
    Ok(parsed)
}

/// A file the caller wants changes for. Built by the caller from `FileId`s; this crate keeps no name
/// (ADR 0086, section 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchTarget {
    /// The caller's own index for this target; returned with each match.
    pub index: usize,
    /// The folder the file is in. A version 2 record's parent is compared with this.
    pub parent_index_64: u64,
    /// The folder the file is in. A version 3 record's parent is compared with this.
    pub parent_id_128: [u8; 16],
    /// The file's own identifiers, when the file still exists. `None` when it is gone.
    pub file: Option<(u64, [u8; 16])>,
    /// The file's name (last path segment) as UTF-16 code units.
    pub name: Vec<u16>,
}

/// Which change a matching record recorded (ADR 0086, section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeKind {
    /// `REASON_FILE_DELETE`
    Deleted,
    /// `REASON_RENAME_OLD_NAME`
    RenamedFrom,
    /// `REASON_RENAME_NEW_NAME`
    RenamedTo,
}

/// One match: an index, a kind and a time only. Never a name, a USN or a file reference (ADR 0086,
/// section 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalMatch {
    /// The `index` of the target that matched.
    pub target: usize,
    /// The change the record recorded.
    pub kind: ChangeKind,
    /// `TimeStamp` of the record, as `UsnRecord::written`.
    pub written: Option<Timestamp>,
}

/// One buffer's matches (ADR 0086, section 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnMatches {
    /// As `UsnBuffer::next_usn`.
    pub next_usn: i64,
    /// In buffer order; within one record, in `ChangeKind` order.
    pub matches: Vec<JournalMatch>,
    /// As `UsnBuffer::damage`: matches before a damaged record are kept.
    pub damage: Option<ParseError>,
}

/// Finds the records in one output buffer that delete or rename one of `targets` (ADR 0086, section 2).
///
/// Only a record whose `Reason` holds `REASON_FILE_DELETE`, `REASON_RENAME_OLD_NAME` or
/// `REASON_RENAME_NEW_NAME` is compared. It matches a target when its parent is the target's parent
/// and its name is the target's name, ignoring ASCII case only; or when the target has a file
/// reference and the record's own file reference is that one. The walk is the one `parse_buffer`
/// makes, with the same damage handling.
///
/// # Errors
///
/// `ParseError::Truncated` when the buffer is shorter than `HEADER_LEN`, as `parse_buffer`.
pub fn match_buffer(bytes: &[u8], targets: &[MatchTarget]) -> Result<UsnMatches, ParseError> {
    let next_usn = header_usn(bytes)?;
    let mut matches = Vec::new();
    let damage = walk(bytes, |record, step| {
        let Step::Record(usn) = step else {
            return Ok(());
        };
        let kinds = change_kinds(usn.reason);
        if kinds.is_empty() {
            return Ok(());
        }
        // A damaged name range stops the walk, but only for a record that could match.
        let name = name_bytes(record, usn.major_version)?;
        for target in targets {
            let by_parent = match usn.parent {
                ParentReference::Index64(parent) => parent == target.parent_index_64,
                ParentReference::Id128(parent) => parent == target.parent_id_128,
            };
            let by_name = by_parent && same_name(name, &target.name);
            let by_file = target
                .file
                .is_some_and(|file| file_matches(record, usn.major_version, file));
            if by_name || by_file {
                for &kind in &kinds {
                    matches.push(JournalMatch {
                        target: target.index,
                        kind,
                        written: usn.written,
                    });
                }
            }
        }
        Ok(())
    });
    Ok(UsnMatches {
        next_usn,
        matches,
        damage,
    })
}

/// The USN every buffer begins with.
fn header_usn(bytes: &[u8]) -> Result<i64, ParseError> {
    let Some(header) = bytes.first_chunk::<HEADER_LEN>() else {
        return Err(ParseError::Truncated {
            expected: HEADER_LEN,
            found: bytes.len(),
        });
    };
    Ok(i64::from_le_bytes(*header))
}

/// Walks the records after the USN header in buffer order, handing each record's bytes and parsed
/// form to `visit`. Returns the damage that stopped the walk, if any: a damaged record, or an error
/// `visit` returns. Nothing after either is read.
fn walk<'a>(
    bytes: &'a [u8],
    mut visit: impl FnMut(&'a [u8], Step) -> Result<(), ParseError>,
) -> Option<ParseError> {
    let mut offset = HEADER_LEN;
    while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
        let (step, record) = match record_at(rest) {
            Ok(found) => found,
            Err(damage) => return Some(damage),
        };
        if let Err(damage) = visit(record, step) {
            return Some(damage);
        }
        // `record` is at least RECORD_HEADER_LEN and at most `rest.len()`, so this always
        // advances and never passes the end by more than the alignment.
        offset = offset.saturating_add(record.len().next_multiple_of(ALIGNMENT));
    }
    None
}

enum Step {
    Record(UsnRecord),
    SkippedVersion4,
}

/// The change kinds a record's `Reason` holds, in `ChangeKind` order. Empty for a record that is not
/// compared.
fn change_kinds(reason: u32) -> Vec<ChangeKind> {
    [
        (REASON_FILE_DELETE, ChangeKind::Deleted),
        (REASON_RENAME_OLD_NAME, ChangeKind::RenamedFrom),
        (REASON_RENAME_NEW_NAME, ChangeKind::RenamedTo),
    ]
    .into_iter()
    .filter(|(flag, _)| reason & *flag != 0)
    .map(|(_, kind)| kind)
    .collect()
}

/// The name's UTF-16 bytes, as `FileNameLength` and `FileNameOffset` place them in the record. A name
/// of odd length, or one that runs past the record, is damage.
fn name_bytes(record: &[u8], major_version: u16) -> Result<&[u8], ParseError> {
    let (length_at, offset_at) = if major_version == 3 {
        (V3_NAME_LENGTH_AT, V3_NAME_OFFSET_AT)
    } else {
        (V2_NAME_LENGTH_AT, V2_NAME_OFFSET_AT)
    };
    let length = usize::from(u16_at(record, length_at)?);
    let offset = usize::from(u16_at(record, offset_at)?);
    let damaged = |detail: &str| ParseError::Malformed {
        field: "file_name",
        detail: detail.to_owned(),
    };
    if length % 2 == 1 {
        return Err(damaged("a file name of odd length"));
    }
    offset
        .checked_add(length)
        .and_then(|end| record.get(offset..end))
        .ok_or_else(|| damaged("a file name outside its record"))
}

/// Whether a record's name is `target`, ignoring ASCII case only.
fn same_name(record_name: &[u8], target: &[u16]) -> bool {
    record_name
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| fold_ascii_case(u16::from_le_bytes(*unit)))
        .eq(target.iter().map(|&unit| fold_ascii_case(unit)))
}

/// Folds `A` to `Z` to `a` to `z` in one UTF-16 unit and leaves every other unit alone. A wider fold
/// would make names that differ only by an accent compare equal (ADR 0086, section 2).
fn fold_ascii_case(unit: u16) -> u16 {
    if (0x41..=0x5A).contains(&unit) {
        unit + 0x20
    } else {
        unit
    }
}

/// Whether a record's own file reference is `file`: a version 2 record's 64-bit number at offset 8,
/// or a version 3 record's 128-bit identifier at offsets 8 to 24.
fn file_matches(record: &[u8], major_version: u16, file: (u64, [u8; 16])) -> bool {
    if major_version == 3 {
        record
            .get(8..24)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            == Some(file.1)
    } else {
        u64_at(record, 8).ok() == Some(file.0)
    }
}

/// The record at the start of `rest`, and its bytes. The record's length is `RecordLength`.
fn record_at(rest: &[u8]) -> Result<(Step, &[u8]), ParseError> {
    let Some(head) = rest.first_chunk::<RECORD_HEADER_LEN>() else {
        return Err(ParseError::Truncated {
            expected: RECORD_HEADER_LEN,
            found: rest.len(),
        });
    };
    let length = usize::try_from(u32::from_le_bytes([head[0], head[1], head[2], head[3]]))
        .unwrap_or(usize::MAX);
    let major_version = u16::from_le_bytes([head[4], head[5]]);
    if length < RECORD_HEADER_LEN {
        return Err(ParseError::Malformed {
            field: "record_length",
            detail: "a record length shorter than a record header".to_owned(),
        });
    }
    let Some(record) = rest.get(..length) else {
        return Err(ParseError::Truncated {
            expected: length,
            found: rest.len(),
        });
    };
    let step = match major_version {
        2 => Step::Record(version_2(record)?),
        3 => Step::Record(version_3(record)?),
        4 => Step::SkippedVersion4,
        _ => {
            return Err(ParseError::Malformed {
                field: "major_version",
                detail: "a change journal major version this parser does not read".to_owned(),
            });
        }
    };
    Ok((step, record))
}

fn version_2(record: &[u8]) -> Result<UsnRecord, ParseError> {
    fixed(record, V2_FIXED_LEN)?;
    let written = u64_at(record, 32)?;
    Ok(UsnRecord {
        major_version: 2,
        parent: ParentReference::Index64(u64_at(record, 16)?),
        written: filetime::to_timestamp(written),
        reason: u32_at(record, 40)?,
    })
}

fn version_3(record: &[u8]) -> Result<UsnRecord, ParseError> {
    fixed(record, V3_FIXED_LEN)?;
    let parent = record
        .get(24..40)
        .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
        .ok_or(ParseError::Truncated {
            expected: 40,
            found: record.len(),
        })?;
    let written = u64_at(record, 48)?;
    Ok(UsnRecord {
        major_version: 3,
        parent: ParentReference::Id128(parent),
        written: filetime::to_timestamp(written),
        reason: u32_at(record, 56)?,
    })
}

fn fixed(record: &[u8], needed: usize) -> Result<(), ParseError> {
    if record.len() < needed {
        return Err(ParseError::Truncated {
            expected: needed,
            found: record.len(),
        });
    }
    Ok(())
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, ParseError> {
    bytes
        .get(at..)
        .and_then(|rest| rest.first_chunk::<2>())
        .map(|value| u16::from_le_bytes(*value))
        .ok_or(ParseError::Truncated {
            expected: at + 2,
            found: bytes.len(),
        })
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64, ParseError> {
    bytes
        .get(at..)
        .and_then(|rest| rest.first_chunk::<8>())
        .map(|value| u64::from_le_bytes(*value))
        .ok_or(ParseError::Truncated {
            expected: at + 8,
            found: bytes.len(),
        })
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, ParseError> {
    bytes
        .get(at..)
        .and_then(|rest| rest.first_chunk::<4>())
        .map(|value| u32::from_le_bytes(*value))
        .ok_or(ParseError::Truncated {
            expected: at + 4,
            found: bytes.len(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRITTEN: u64 = 133_000_000_000_000_000;

    /// A version 3 record with a two-character name, 80 bytes, which is already aligned.
    fn v3(parent: [u8; 16], written: u64, reason: u32) -> Vec<u8> {
        let mut record = vec![0u8; 80];
        record[0..4].copy_from_slice(&80u32.to_le_bytes());
        record[4..6].copy_from_slice(&3u16.to_le_bytes());
        record[8..24].copy_from_slice(&[0xAA; 16]);
        record[24..40].copy_from_slice(&parent);
        record[40..48].copy_from_slice(&4096i64.to_le_bytes());
        record[48..56].copy_from_slice(&written.to_le_bytes());
        record[56..60].copy_from_slice(&reason.to_le_bytes());
        record[72..74].copy_from_slice(&4u16.to_le_bytes());
        record[74..76].copy_from_slice(&76u16.to_le_bytes());
        record[76..80].copy_from_slice(&[b'a', 0, b'b', 0]);
        record
    }

    /// A version 2 record with a two-character name, 64 bytes.
    fn v2(parent: u64, written: u64, reason: u32) -> Vec<u8> {
        let mut record = vec![0u8; 64];
        record[0..4].copy_from_slice(&64u32.to_le_bytes());
        record[4..6].copy_from_slice(&2u16.to_le_bytes());
        record[8..16].copy_from_slice(&0xAAAA_u64.to_le_bytes());
        record[16..24].copy_from_slice(&parent.to_le_bytes());
        record[24..32].copy_from_slice(&4096i64.to_le_bytes());
        record[32..40].copy_from_slice(&written.to_le_bytes());
        record[40..44].copy_from_slice(&reason.to_le_bytes());
        record[56..58].copy_from_slice(&4u16.to_le_bytes());
        record[58..60].copy_from_slice(&60u16.to_le_bytes());
        record[60..64].copy_from_slice(&[b'a', 0, b'b', 0]);
        record
    }

    /// A version 4 record's common header and nothing a parser reads past it, 64 bytes.
    fn v4() -> Vec<u8> {
        let mut record = vec![0u8; 64];
        record[0..4].copy_from_slice(&64u32.to_le_bytes());
        record[4..6].copy_from_slice(&4u16.to_le_bytes());
        record
    }

    fn buffer(next_usn: i64, records: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = next_usn.to_le_bytes().to_vec();
        for record in records {
            bytes.extend_from_slice(record);
        }
        bytes
    }

    /// A name as the UTF-16 code units a record and a target both carry.
    fn wide(name: &str) -> Vec<u16> {
        name.encode_utf16().collect()
    }

    /// A version 2 record carrying `name`, its `RecordLength` padded to the alignment.
    fn v2_named(parent: u64, file_ref: u64, name: &[u16], reason: u32) -> Vec<u8> {
        let name_bytes = name.len() * 2;
        let length = (V2_FIXED_LEN + name_bytes).next_multiple_of(ALIGNMENT);
        let mut record = vec![0u8; length];
        record[0..4].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
        record[4..6].copy_from_slice(&2u16.to_le_bytes());
        record[8..16].copy_from_slice(&file_ref.to_le_bytes());
        record[16..24].copy_from_slice(&parent.to_le_bytes());
        record[32..40].copy_from_slice(&WRITTEN.to_le_bytes());
        record[40..44].copy_from_slice(&reason.to_le_bytes());
        record[56..58].copy_from_slice(&u16::try_from(name_bytes).unwrap().to_le_bytes());
        record[58..60].copy_from_slice(&u16::try_from(V2_FIXED_LEN).unwrap().to_le_bytes());
        for (slot, unit) in record[V2_FIXED_LEN..].as_chunks_mut::<2>().0.iter_mut().zip(name) {
            slot.copy_from_slice(&unit.to_le_bytes());
        }
        record
    }

    /// A version 3 record carrying `name`, its `RecordLength` padded to the alignment.
    fn v3_named(parent: [u8; 16], file_ref: [u8; 16], name: &[u16], reason: u32) -> Vec<u8> {
        let name_bytes = name.len() * 2;
        let length = (V3_FIXED_LEN + name_bytes).next_multiple_of(ALIGNMENT);
        let mut record = vec![0u8; length];
        record[0..4].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
        record[4..6].copy_from_slice(&3u16.to_le_bytes());
        record[8..24].copy_from_slice(&file_ref);
        record[24..40].copy_from_slice(&parent);
        record[48..56].copy_from_slice(&WRITTEN.to_le_bytes());
        record[56..60].copy_from_slice(&reason.to_le_bytes());
        record[72..74].copy_from_slice(&u16::try_from(name_bytes).unwrap().to_le_bytes());
        record[74..76].copy_from_slice(&u16::try_from(V3_FIXED_LEN).unwrap().to_le_bytes());
        for (slot, unit) in record[V3_FIXED_LEN..].as_chunks_mut::<2>().0.iter_mut().zip(name) {
            slot.copy_from_slice(&unit.to_le_bytes());
        }
        record
    }

    /// A target in the folder `v2_named(7, ..)` and `v3_named([1; 16], ..)` records are in, with no
    /// file identifiers. Tests that need the identifiers set them with struct update syntax.
    fn target(index: usize, name: &str) -> MatchTarget {
        MatchTarget {
            index,
            parent_index_64: 7,
            parent_id_128: [1; 16],
            file: None,
            name: wide(name),
        }
    }

    /// The match a record with `kind` in a buffer written at `WRITTEN` gives for `target`.
    fn found(target: usize, kind: ChangeKind) -> JournalMatch {
        JournalMatch {
            target,
            kind,
            written: filetime::to_timestamp(WRITTEN),
        }
    }

    #[test]
    fn version_3_records_are_read_in_order() {
        let bytes = buffer(
            9000,
            &[
                v3([1; 16], WRITTEN, REASON_FILE_CREATE),
                v3([2; 16], WRITTEN + 1, REASON_FILE_DELETE | REASON_CLOSE),
            ],
        );
        let parsed = parse_buffer(&bytes).unwrap();
        assert_eq!(parsed.next_usn, 9000);
        assert_eq!(parsed.damage, None);
        assert_eq!(parsed.skipped_version_4, 0);
        assert_eq!(
            parsed.records,
            vec![
                UsnRecord {
                    major_version: 3,
                    parent: ParentReference::Id128([1; 16]),
                    written: filetime::to_timestamp(WRITTEN),
                    reason: REASON_FILE_CREATE,
                },
                UsnRecord {
                    major_version: 3,
                    parent: ParentReference::Id128([2; 16]),
                    written: filetime::to_timestamp(WRITTEN + 1),
                    reason: REASON_FILE_DELETE | REASON_CLOSE,
                },
            ]
        );
    }

    #[test]
    fn a_version_2_record_names_its_parent_by_a_64_bit_index() {
        let parsed = parse_buffer(&buffer(
            1,
            &[v2(0x0005_0000_0000_1234, WRITTEN, REASON_DATA_EXTEND)],
        ))
        .unwrap();
        assert_eq!(parsed.damage, None);
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].major_version, 2);
        assert_eq!(
            parsed.records[0].parent,
            ParentReference::Index64(0x0005_0000_0000_1234)
        );
        assert_eq!(parsed.records[0].reason, REASON_DATA_EXTEND);
    }

    #[test]
    fn a_version_4_record_is_counted_and_skipped() {
        let bytes = buffer(1, &[v4(), v3([1; 16], WRITTEN, REASON_CLOSE)]);
        let parsed = parse_buffer(&bytes).unwrap();
        assert_eq!(parsed.skipped_version_4, 1);
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.damage, None);
    }

    /// Two records that differ only in their names parse to the same value: nothing of the name is
    /// kept, not even its length.
    #[test]
    fn nothing_of_the_file_name_is_kept() {
        let first = v3([1; 16], WRITTEN, REASON_FILE_CREATE);
        let mut second = first.clone();
        second[76..80].copy_from_slice(&[b'z', 0, b'q', 0]);
        assert_eq!(
            parse_buffer(&buffer(1, &[first])).unwrap(),
            parse_buffer(&buffer(1, &[second])).unwrap()
        );
    }

    /// Microsoft's own sample advances by `RecordLength` with no check, so a zero never advances. Here
    /// it stops the buffer and keeps what came before.
    #[test]
    fn a_record_length_of_zero_stops_the_buffer_instead_of_looping() {
        let mut zero = v3([2; 16], WRITTEN, REASON_CLOSE);
        zero[0..4].copy_from_slice(&0u32.to_le_bytes());
        let parsed = parse_buffer(&buffer(1, &[v3([1; 16], WRITTEN, REASON_CLOSE), zero])).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert!(matches!(
            parsed.damage,
            Some(ParseError::Malformed {
                field: "record_length",
                ..
            })
        ));
    }

    #[test]
    fn a_record_length_past_the_end_of_the_buffer_is_truncated_and_keeps_earlier_records() {
        let mut long = v3([2; 16], WRITTEN, REASON_CLOSE);
        long[0..4].copy_from_slice(&4000u32.to_le_bytes());
        let parsed = parse_buffer(&buffer(1, &[v3([1; 16], WRITTEN, REASON_CLOSE), long])).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(
            parsed.damage,
            Some(ParseError::Truncated {
                expected: 4000,
                found: 80
            })
        );
    }

    #[test]
    fn a_record_shorter_than_its_version_needs_is_truncated() {
        let mut short = v3([1; 16], WRITTEN, REASON_CLOSE);
        short[0..4].copy_from_slice(&16u32.to_le_bytes());
        let parsed = parse_buffer(&buffer(1, &[short])).unwrap();
        assert!(parsed.records.is_empty());
        assert_eq!(
            parsed.damage,
            Some(ParseError::Truncated {
                expected: 76,
                found: 16
            })
        );
    }

    #[test]
    fn an_unknown_major_version_stops_the_buffer() {
        let mut unknown = v3([1; 16], WRITTEN, REASON_CLOSE);
        unknown[4..6].copy_from_slice(&5u16.to_le_bytes());
        let parsed =
            parse_buffer(&buffer(1, &[unknown, v3([2; 16], WRITTEN, REASON_CLOSE)])).unwrap();
        assert!(parsed.records.is_empty());
        assert!(matches!(
            parsed.damage,
            Some(ParseError::Malformed {
                field: "major_version",
                ..
            })
        ));
    }

    #[test]
    fn a_record_that_does_not_end_on_the_alignment_is_followed_from_the_next_boundary() {
        let mut odd = v3([1; 16], WRITTEN, REASON_CLOSE);
        odd.truncate(78);
        odd[0..4].copy_from_slice(&78u32.to_le_bytes());
        odd[72..74].copy_from_slice(&2u16.to_le_bytes());
        odd.extend_from_slice(&[0, 0]);
        let parsed = parse_buffer(&buffer(1, &[odd, v3([2; 16], WRITTEN, REASON_CLOSE)])).unwrap();
        assert_eq!(parsed.damage, None);
        assert_eq!(parsed.records.len(), 2);
    }

    #[test]
    fn a_timestamp_out_of_range_is_none_and_the_record_still_counts() {
        let parsed = parse_buffer(&buffer(1, &[v3([1; 16], u64::MAX, REASON_CLOSE)])).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].written, None);
    }

    #[test]
    fn seven_bytes_is_truncated_and_eight_is_an_empty_buffer() {
        assert_eq!(
            parse_buffer(&[0; 7]),
            Err(ParseError::Truncated {
                expected: 8,
                found: 7
            })
        );
        let empty = parse_buffer(&42i64.to_le_bytes()).unwrap();
        assert_eq!(empty.next_usn, 42);
        assert!(empty.records.is_empty());
        assert_eq!(empty.damage, None);
    }

    #[test]
    fn trailing_bytes_shorter_than_a_record_header_are_damage() {
        let mut bytes = buffer(1, &[v3([1; 16], WRITTEN, REASON_CLOSE)]);
        bytes.extend_from_slice(&[1, 2, 3]);
        let parsed = parse_buffer(&bytes).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(
            parsed.damage,
            Some(ParseError::Truncated {
                expected: 8,
                found: 3
            })
        );
    }

    #[test]
    fn no_length_panics() {
        let mut bytes = buffer(
            1,
            &[
                v3([1; 16], WRITTEN, REASON_CLOSE),
                v2(7, WRITTEN, REASON_CLOSE),
                v4(),
            ],
        );
        bytes.extend((0..=255u8).cycle().take(300));
        for length in 0..bytes.len() {
            let _ = parse_buffer(&bytes[..length]);
        }
    }

    #[test]
    fn a_version_3_record_matches_by_parent_and_name_for_each_kind() {
        let kinds = [
            (REASON_FILE_DELETE, ChangeKind::Deleted),
            (REASON_RENAME_OLD_NAME, ChangeKind::RenamedFrom),
            (REASON_RENAME_NEW_NAME, ChangeKind::RenamedTo),
        ];
        for (reason, kind) in kinds {
            let bytes = buffer(1, &[v3_named([1; 16], [9; 16], &wide("a.exe"), reason)]);
            let matched = match_buffer(&bytes, &[target(0, "a.exe")]).unwrap();
            assert_eq!(matched.next_usn, 1);
            assert_eq!(matched.damage, None);
            assert_eq!(matched.matches, vec![found(0, kind)]);
        }
    }

    #[test]
    fn a_version_2_record_matches_by_parent_index_and_name() {
        let bytes = buffer(1, &[v2_named(7, 9, &wide("a.exe"), REASON_FILE_DELETE)]);
        let matched = match_buffer(&bytes, &[target(0, "a.exe")]).unwrap();
        assert_eq!(matched.damage, None);
        assert_eq!(matched.matches, vec![found(0, ChangeKind::Deleted)]);
    }

    #[test]
    fn a_name_differing_only_in_ascii_case_matches_but_a_non_ascii_letter_does_not() {
        let upper = buffer(1, &[v3_named([1; 16], [9; 16], &wide("A.EXE"), REASON_FILE_DELETE)]);
        let matched = match_buffer(&upper, &[target(0, "a.exe")]).unwrap();
        assert_eq!(matched.matches, vec![found(0, ChangeKind::Deleted)]);

        // U+00C9 is 'É' and U+00E9 is 'é': a fold beyond ASCII would make these equal.
        let accented = buffer(
            1,
            &[v2_named(7, 9, &wide("\u{00C9}.exe"), REASON_FILE_DELETE)],
        );
        let matched = match_buffer(&accented, &[target(0, "\u{00E9}.exe")]).unwrap();
        assert!(matched.matches.is_empty());
    }

    #[test]
    fn a_version_2_record_matches_a_target_by_its_own_file_reference_under_another_name() {
        let bytes = buffer(1, &[v2_named(7, 9, &wide("new.exe"), REASON_FILE_DELETE)]);
        let tracked = MatchTarget {
            parent_index_64: 1,
            file: Some((9, [0; 16])),
            ..target(0, "old.exe")
        };
        let matched = match_buffer(&bytes, &[tracked]).unwrap();
        assert_eq!(matched.matches, vec![found(0, ChangeKind::Deleted)]);
    }

    #[test]
    fn a_version_3_record_matches_a_target_by_its_own_file_reference_under_another_name() {
        let bytes = buffer(
            1,
            &[v3_named([1; 16], [0x55; 16], &wide("new.exe"), REASON_FILE_DELETE)],
        );
        let tracked = MatchTarget {
            parent_id_128: [2; 16],
            file: Some((0, [0x55; 16])),
            ..target(0, "old.exe")
        };
        let matched = match_buffer(&bytes, &[tracked]).unwrap();
        assert_eq!(matched.matches, vec![found(0, ChangeKind::Deleted)]);
    }

    #[test]
    fn a_record_in_the_right_folder_under_another_name_does_not_match() {
        let v2_bytes = buffer(1, &[v2_named(7, 9, &wide("other.exe"), REASON_FILE_DELETE)]);
        let matched = match_buffer(&v2_bytes, &[target(0, "a.exe")]).unwrap();
        assert!(matched.matches.is_empty());

        let v3_bytes = buffer(
            1,
            &[v3_named([1; 16], [9; 16], &wide("other.exe"), REASON_FILE_DELETE)],
        );
        let matched = match_buffer(&v3_bytes, &[target(0, "a.exe")]).unwrap();
        assert!(matched.matches.is_empty());
    }

    #[test]
    fn a_record_with_the_right_name_in_another_folder_does_not_match() {
        let v2_bytes = buffer(1, &[v2_named(8, 9, &wide("a.exe"), REASON_FILE_DELETE)]);
        let matched = match_buffer(&v2_bytes, &[target(0, "a.exe")]).unwrap();
        assert!(matched.matches.is_empty());

        let v3_bytes = buffer(
            1,
            &[v3_named([3; 16], [9; 16], &wide("a.exe"), REASON_FILE_DELETE)],
        );
        let matched = match_buffer(&v3_bytes, &[target(0, "a.exe")]).unwrap();
        assert!(matched.matches.is_empty());
    }

    #[test]
    fn a_record_with_neither_delete_nor_rename_does_not_match_even_by_file_reference() {
        let reason = REASON_DATA_EXTEND | REASON_CLOSE;

        let v2_bytes = buffer(1, &[v2_named(7, 9, &wide("a.exe"), reason)]);
        let tracked = MatchTarget {
            file: Some((9, [0; 16])),
            ..target(0, "a.exe")
        };
        let matched = match_buffer(&v2_bytes, &[tracked]).unwrap();
        assert!(matched.matches.is_empty());

        let v3_bytes = buffer(
            1,
            &[v3_named([1; 16], [0x55; 16], &wide("a.exe"), reason)],
        );
        let tracked = MatchTarget {
            file: Some((0, [0x55; 16])),
            ..target(0, "a.exe")
        };
        let matched = match_buffer(&v3_bytes, &[tracked]).unwrap();
        assert!(matched.matches.is_empty());
    }

    #[test]
    fn a_record_matching_a_target_by_both_rules_is_reported_once() {
        let v2_bytes = buffer(1, &[v2_named(7, 9, &wide("a.exe"), REASON_FILE_DELETE)]);
        let tracked = MatchTarget {
            file: Some((9, [0; 16])),
            ..target(0, "a.exe")
        };
        let matched = match_buffer(&v2_bytes, &[tracked]).unwrap();
        assert_eq!(matched.matches, vec![found(0, ChangeKind::Deleted)]);

        let v3_bytes = buffer(
            1,
            &[v3_named([1; 16], [0x55; 16], &wide("a.exe"), REASON_FILE_DELETE)],
        );
        let tracked = MatchTarget {
            file: Some((0, [0x55; 16])),
            ..target(0, "a.exe")
        };
        let matched = match_buffer(&v3_bytes, &[tracked]).unwrap();
        assert_eq!(matched.matches, vec![found(0, ChangeKind::Deleted)]);
    }

    #[test]
    fn a_delete_and_rename_new_name_record_gives_two_matches_deleted_then_renamed_to() {
        let bytes = buffer(
            1,
            &[v3_named(
                [1; 16],
                [9; 16],
                &wide("a.exe"),
                REASON_FILE_DELETE | REASON_RENAME_NEW_NAME,
            )],
        );
        let matched = match_buffer(&bytes, &[target(0, "a.exe")]).unwrap();
        assert_eq!(matched.damage, None);
        assert_eq!(
            matched.matches,
            vec![found(0, ChangeKind::Deleted), found(0, ChangeKind::RenamedTo)]
        );
    }

    #[test]
    fn two_targets_each_matched_by_one_record_are_returned_in_buffer_order() {
        let bytes = buffer(
            1,
            &[
                v2_named(7, 9, &wide("a.exe"), REASON_FILE_DELETE),
                v2_named(7, 10, &wide("b.exe"), REASON_RENAME_OLD_NAME),
            ],
        );
        let targets = [target(1, "b.exe"), target(3, "a.exe")];
        let matched = match_buffer(&bytes, &targets).unwrap();
        assert_eq!(
            matched.matches,
            vec![found(3, ChangeKind::Deleted), found(1, ChangeKind::RenamedFrom)]
        );
    }

    #[test]
    fn a_damaged_record_keeps_the_matches_before_it() {
        let mut long = v2_named(7, 10, &wide("a.exe"), REASON_FILE_DELETE);
        long[0..4].copy_from_slice(&4000u32.to_le_bytes());
        let bytes = buffer(
            1,
            &[
                v2_named(7, 9, &wide("a.exe"), REASON_FILE_DELETE),
                long,
                v2_named(7, 11, &wide("a.exe"), REASON_FILE_DELETE),
            ],
        );
        let matched = match_buffer(&bytes, &[target(0, "a.exe")]).unwrap();
        assert_eq!(matched.matches, vec![found(0, ChangeKind::Deleted)]);
        assert!(matches!(
            matched.damage,
            Some(ParseError::Truncated { .. })
        ));
    }

    #[test]
    fn a_version_4_record_between_matches_is_skipped() {
        let bytes = buffer(
            1,
            &[
                v2_named(7, 9, &wide("a.exe"), REASON_FILE_DELETE),
                v4(),
                v3_named([1; 16], [9; 16], &wide("a.exe"), REASON_RENAME_NEW_NAME),
            ],
        );
        let matched = match_buffer(&bytes, &[target(0, "a.exe")]).unwrap();
        assert_eq!(matched.damage, None);
        assert_eq!(
            matched.matches,
            vec![found(0, ChangeKind::Deleted), found(0, ChangeKind::RenamedTo)]
        );
    }

    #[test]
    fn an_unknown_major_version_stops_the_match_walk() {
        let mut unknown = v3_named([1; 16], [9; 16], &wide("a.exe"), REASON_FILE_DELETE);
        unknown[4..6].copy_from_slice(&5u16.to_le_bytes());
        let bytes = buffer(
            1,
            &[
                v2_named(7, 9, &wide("a.exe"), REASON_FILE_DELETE),
                unknown,
                v2_named(7, 11, &wide("a.exe"), REASON_FILE_DELETE),
            ],
        );
        let matched = match_buffer(&bytes, &[target(0, "a.exe")]).unwrap();
        assert_eq!(matched.matches, vec![found(0, ChangeKind::Deleted)]);
        assert!(matches!(
            matched.damage,
            Some(ParseError::Malformed {
                field: "major_version",
                ..
            })
        ));
    }

    #[test]
    fn a_buffer_shorter_than_the_usn_header_is_truncated() {
        assert_eq!(
            match_buffer(&[0; 7], &[target(0, "a.exe")]),
            Err(ParseError::Truncated {
                expected: 8,
                found: 7
            })
        );
    }

    /// The matches are the only output that leaves the parser, so no name may appear in their debug
    /// form: twenty records with names, and only the target's one matches.
    #[test]
    fn the_matches_show_no_file_name_even_in_debug_form() {
        let mut records = Vec::new();
        for index in 0..20u8 {
            let name = wide(&format!("secret-name-{index:02}.exe"));
            records.push(v3_named([1; 16], [index; 16], &name, REASON_FILE_DELETE));
        }
        let bytes = buffer(1, &records);
        let matched = match_buffer(&bytes, &[target(0, "secret-name-07.exe")]).unwrap();
        assert_eq!(matched.matches, vec![found(0, ChangeKind::Deleted)]);
        let shown = format!("{matched:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(!shown.contains("exe"), "{shown}");
    }

    #[test]
    fn a_name_range_outside_the_record_is_damage_on_a_delete_record() {
        let mut bad = v3_named([1; 16], [9; 16], &wide("a.exe"), REASON_FILE_DELETE);
        bad[74..76].copy_from_slice(&0xFFF0u16.to_le_bytes());
        let matched = match_buffer(&buffer(1, &[bad]), &[target(0, "a.exe")]).unwrap();
        assert!(matched.matches.is_empty());
        assert!(matches!(
            matched.damage,
            Some(ParseError::Malformed {
                field: "file_name",
                ..
            })
        ));
    }

    #[test]
    fn the_same_bad_name_range_on_a_data_extend_record_is_not_damage() {
        let mut bad = v3_named([1; 16], [9; 16], &wide("a.exe"), REASON_DATA_EXTEND);
        bad[74..76].copy_from_slice(&0xFFF0u16.to_le_bytes());
        let matched = match_buffer(&buffer(1, &[bad]), &[target(0, "a.exe")]).unwrap();
        assert_eq!(matched.damage, None);
        assert!(matched.matches.is_empty());
    }

    #[test]
    fn parse_buffer_output_is_unchanged_for_buffers_with_names() {
        let bytes = buffer(
            9000,
            &[
                v3_named([1; 16], [9; 16], &wide("a.exe"), REASON_FILE_DELETE),
                v2_named(7, 10, &wide("b.exe"), REASON_CLOSE),
            ],
        );
        assert_eq!(
            parse_buffer(&bytes).unwrap(),
            UsnBuffer {
                next_usn: 9000,
                records: vec![
                    UsnRecord {
                        major_version: 3,
                        parent: ParentReference::Id128([1; 16]),
                        written: filetime::to_timestamp(WRITTEN),
                        reason: REASON_FILE_DELETE,
                    },
                    UsnRecord {
                        major_version: 2,
                        parent: ParentReference::Index64(7),
                        written: filetime::to_timestamp(WRITTEN),
                        reason: REASON_CLOSE,
                    },
                ],
                skipped_version_4: 0,
                damage: None,
            }
        );
    }
}
