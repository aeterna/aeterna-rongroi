// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Background Activity Moderator (BAM) registry values.
//!
//! BAM lives at `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}`, with one
//! registry value per executable. **The value name is the executable's path; the value data is what
//! this module parses.** The path, the SID and the reading of the registry all belong to a collector
//! — which is why a fixture here is a byte array and needs no path, no user name and no SID at all.
//!
//! # Layout
//!
//! Little-endian:
//!
//! | Offset | Meaning |
//! |---|---|
//! | 0..8 | 64-bit `FILETIME`, last execution time, UTC |
//! | 8..12 | a DWORD tied to Windows power-throttling ("moderation state") |
//! | 12..24 | not documented by any public source found — **given no meaning here** |
//!
//! Bytes from offset 12 on are kept verbatim in [`BamEntry::unparsed_tail`] and are not named,
//! counted as fields, or interpreted. A later Windows build may give them a meaning; until something
//! establishes one, inventing it would put a guess into evidence a server admin is asked to trust.
//!
//! # What is unverified here
//!
//! The 24-byte layout above was confirmed by two independent public write-ups, but **both tested only
//! Windows 10 builds 18363 and 19592, from 2019–2020**. Nothing confirms the layout is unchanged on
//! current Windows 11, and this repository has no corpus to check it against. That is exactly why
//! this parser **accepts any length of at least 8 bytes** instead of requiring 24: a value that is
//! longer, shorter or differently shaped is decoded as far as it is understood and handed back whole,
//! rather than rejected for disagreeing with a five-year-old write-up (ADR 0013).

use jiff::Timestamp;

use crate::error::ParseError;
use crate::filetime;

/// Smallest value this parser can decode: the `FILETIME` on its own.
const MINIMUM_LEN: usize = 8;
/// Where the moderation state ends and the bytes with no established meaning begin.
const TAIL_OFFSET: usize = 12;

/// One BAM registry value: when BAM last recorded the executable running.
///
/// Which executable that is, is the *name* of the registry value and not part of this structure —
/// see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BamEntry {
    /// The raw 64-bit `FILETIME` from bytes 0..8, exactly as it was stored.
    ///
    /// Kept beside the converted [`Self::last_run`] so that nothing read is lost: a value the
    /// conversion cannot represent is still visible here, and a caller that wants to compare
    /// registry values byte for byte can.
    pub last_run_filetime: u64,
    /// The same instant as a UTC timestamp.
    ///
    /// `None` means the raw value does not name an instant this program can represent — a corrupt
    /// or hostile value, not an absent one. It never means the artifact had no timestamp: a
    /// `FILETIME` of zero converts to 1601-01-01T00:00:00Z like any other value, and whether that
    /// means "never ran" is a judgement for the collector and the rule, not for the parser.
    pub last_run: Option<Timestamp>,
    /// Bytes 8..12: a DWORD tied to Windows power-throttling.
    ///
    /// `None` when the value was shorter than 12 bytes, in which case those bytes are in
    /// [`Self::unparsed_tail`] instead.
    pub moderation_state: Option<u32>,
    /// Every byte the parser did not decode, verbatim and in order.
    ///
    /// For a 24-byte value this is bytes 12..24, whose meaning no public source establishes; for a
    /// longer value it is everything past offset 12. It is deliberately not named, split into
    /// fields or interpreted. Keeping it means a later Windows build can be understood from data
    /// this tool already collected, and that a value which is not the documented shape can be shown
    /// as what it was rather than silently trimmed to fit.
    pub unparsed_tail: Vec<u8>,
}

/// Parses one BAM registry value.
///
/// Accepts any length of at least 8 bytes and decodes only what is understood; see the module
/// documentation for why the length is not required to be 24.
///
/// # Errors
///
/// [`ParseError::Truncated`] when there are fewer than 8 bytes, which is too few to hold even the
/// timestamp.
pub fn parse_value(bytes: &[u8]) -> Result<BamEntry, ParseError> {
    let Some(head) = bytes.first_chunk::<MINIMUM_LEN>() else {
        return Err(ParseError::Truncated {
            expected: MINIMUM_LEN,
            found: bytes.len(),
        });
    };
    let last_run_filetime = u64::from_le_bytes(*head);

    let moderation_state = bytes
        .get(MINIMUM_LEN..TAIL_OFFSET)
        .and_then(|field| <[u8; 4]>::try_from(field).ok())
        .map(u32::from_le_bytes);

    // The tail starts wherever decoding stopped, so a value that ends between the two known fields
    // keeps its leftover bytes too. Nothing read is dropped.
    let decoded_len = if moderation_state.is_some() {
        TAIL_OFFSET
    } else {
        MINIMUM_LEN
    };

    Ok(BamEntry {
        last_run_filetime,
        last_run: filetime::to_timestamp(last_run_filetime),
        moderation_state,
        // `get` rather than indexing: this must be total for every length that got this far.
        unparsed_tail: bytes.get(decoded_len..).unwrap_or(&[]).to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::{BamEntry, parse_value};
    use crate::error::ParseError;

    /// 12 bytes of tail, distinct enough that a test can tell them from padding.
    const TAIL: [u8; 12] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB1, 0xB2, 0xB3, 0xC0, 0xC1, 0xC2, 0xC3,
    ];

    /// 2020-01-01T00:00:00Z, as a FILETIME.
    const FILETIME_2020: u64 = 132_223_104_000_000_000;

    fn value(filetime: u64, moderation_state: u32, tail: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&filetime.to_le_bytes());
        bytes.extend_from_slice(&moderation_state.to_le_bytes());
        bytes.extend_from_slice(tail);
        bytes
    }

    fn parsed(bytes: &[u8]) -> BamEntry {
        match parse_value(bytes) {
            Ok(entry) => entry,
            Err(error) => panic!("expected {} bytes to parse: {error}", bytes.len()),
        }
    }

    #[test]
    fn the_documented_twenty_four_byte_value_with_a_zero_moderation_state() {
        let entry = parsed(&value(FILETIME_2020, 0, &TAIL));

        assert_eq!(entry.last_run_filetime, FILETIME_2020);
        assert_eq!(
            entry.last_run.map(|time| time.to_string()),
            Some("2020-01-01T00:00:00Z".to_owned())
        );
        assert_eq!(entry.moderation_state, Some(0));
        assert_eq!(entry.unparsed_tail, TAIL);
    }

    #[test]
    fn the_documented_twenty_four_byte_value_with_a_non_zero_moderation_state() {
        let entry = parsed(&value(FILETIME_2020, 0x0002_0001, &TAIL));

        assert_eq!(entry.moderation_state, Some(0x0002_0001));
        assert_eq!(entry.last_run_filetime, FILETIME_2020);
    }

    /// Both known fields are read little-endian. Written out by hand rather than with `to_le_bytes`,
    /// so that the test would still fail if the parser and the fixture agreed on the wrong order.
    #[test]
    fn both_known_fields_are_little_endian() {
        let bytes = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // FILETIME = 1
            0x02, 0x00, 0x00, 0x00, // moderation state = 2
        ];

        let entry = parsed(&bytes);

        assert_eq!(entry.last_run_filetime, 1);
        assert_eq!(entry.moderation_state, Some(2));
    }

    #[test]
    fn eight_bytes_carry_a_timestamp_and_nothing_else() {
        let entry = parsed(&FILETIME_2020.to_le_bytes());

        assert_eq!(entry.last_run_filetime, FILETIME_2020);
        assert_eq!(entry.moderation_state, None);
        assert!(entry.unparsed_tail.is_empty());
    }

    #[test]
    fn seven_bytes_is_a_typed_error_not_a_panic() {
        assert_eq!(
            parse_value(&[0; 7]),
            Err(ParseError::Truncated {
                expected: 8,
                found: 7
            })
        );
    }

    #[test]
    fn no_bytes_at_all_is_a_typed_error() {
        assert_eq!(
            parse_value(&[]),
            Err(ParseError::Truncated {
                expected: 8,
                found: 0
            })
        );
    }

    /// A longer value is what a newer Windows build would look like. The extra bytes are kept, so
    /// that whoever works out what they mean has them, and so that a report can show that this value
    /// was not the shape the write-ups described.
    #[test]
    fn a_longer_value_keeps_its_tail_instead_of_dropping_it() {
        let long_tail: Vec<u8> = (0..28u8).collect();

        let entry = parsed(&value(FILETIME_2020, 7, &long_tail));

        assert_eq!(entry.moderation_state, Some(7));
        assert_eq!(entry.unparsed_tail, long_tail);
    }

    /// A value that stops between the two known fields still loses nothing: the bytes past the
    /// timestamp are in the tail, even though there are too few of them to be a moderation state.
    #[test]
    fn bytes_too_short_to_be_a_moderation_state_are_kept_as_tail() {
        let mut bytes = FILETIME_2020.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0xDE, 0xAD]);

        let entry = parsed(&bytes);

        assert_eq!(entry.moderation_state, None);
        assert_eq!(entry.unparsed_tail, [0xDE, 0xAD]);
    }

    /// Windows writes a zero FILETIME; so does a value that was never filled in. They are the same
    /// bytes, and the parser reports the instant rather than deciding it means "nothing ran". What a
    /// zero means is a judgement for the collector and the rule, which they cannot make if the
    /// parser has already turned it into an absence.
    #[test]
    fn a_filetime_of_zero_is_an_instant_not_a_missing_value() {
        let entry = parsed(&value(0, 0, &TAIL));

        assert_eq!(entry.last_run_filetime, 0);
        assert_eq!(
            entry.last_run.map(|time| time.to_string()),
            Some("1601-01-01T00:00:00Z".to_owned())
        );
    }

    /// A registry value is attacker-controlled data. Every length must return an answer.
    #[test]
    fn no_length_panics() {
        let bytes: Vec<u8> = (0..=255u8).cycle().take(300).collect();
        for length in 0..bytes.len() {
            let _ = parse_value(&bytes[..length]);
        }
    }
}
