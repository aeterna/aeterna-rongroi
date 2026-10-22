// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! UserAssist names and the 72-byte entry Explorer stores for each program opened through the shell.
//!
//! A value name is ROT13 over ASCII letters only. The entry decodes the last-run `FILETIME` and the
//! value at offset 4, and keeps every other byte in the order it appeared.

#[cfg(test)]
mod tests {
    use super::{UserAssistEntry, decode_name, parse_entry};
    use crate::error::ParseError;

    /// A name in the shape Explorer stores, and the same name after ROT13.
    const SAMPLE_NAME: &str = r"P:\Hfref\k\Qbjaybnqf\purng.cat.rkr\";
    const SAMPLE_DECODED: &str = r"C:\Users\x\Downloads\cheat.png.exe\";

    fn parsed(bytes: &[u8]) -> UserAssistEntry {
        match parse_entry(bytes) {
            Ok(entry) => entry,
            Err(error) => panic!("expected {} bytes to parse: {error}", bytes.len()),
        }
    }

    fn truncated(bytes: &[u8]) -> ParseError {
        match parse_entry(bytes) {
            Err(error) => error,
            Ok(_) => panic!("expected {} bytes to be truncated, but they parsed", bytes.len()),
        }
    }

    /// ROT13 changes ASCII letters and nothing else: digits, separators and non-Latin text must
    /// survive a decode unchanged, and decoding twice must return the original name.
    #[test]
    fn decode_name_rot13s_ascii_letters_and_leaves_everything_else_alone() {
        let once = decode_name(SAMPLE_NAME);

        assert_eq!(once, SAMPLE_DECODED);
        assert_eq!(decode_name(&once), SAMPLE_NAME);

        let unchanged = r"0123456789\{}-!_ไทย";
        assert_eq!(decode_name(unchanged), unchanged);
    }

    /// The unparsed bytes are every byte the entry does not decode, in their original order:
    /// 0..4, then 8..60, then 68 onwards.
    #[test]
    fn parse_entry_reads_offset4_filetime_and_keeps_unparsed_bytes_in_order() {
        let mut bytes: Vec<u8> = (0..72u8).collect();
        bytes[4..8].copy_from_slice(&7u32.to_le_bytes());
        bytes[60..68].copy_from_slice(&0x01DC_7ADC_B192_8100u64.to_le_bytes());

        let entry = parsed(&bytes);

        assert_eq!(entry.offset4, 7);
        assert_eq!(entry.last_run_filetime, 0x01DC_7ADC_B192_8100);
        assert_eq!(entry.unparsed.len(), 60);
        assert_eq!(entry.unparsed[0..4], [0, 1, 2, 3]);
        assert_eq!(entry.unparsed[4], 8);
        assert_eq!(entry.unparsed[55], 59);
        assert_eq!(entry.unparsed[56..60], [68, 69, 70, 71]);

        let expected: Vec<u8> = (0u8..4).chain(8..60).chain(68..72).collect();
        assert_eq!(entry.unparsed, expected);
    }

    /// Fewer than 72 bytes cannot hold the entry. A longer entry is still parsed and everything past
    /// byte 72 is kept in `unparsed`, not dropped.
    #[test]
    fn parse_entry_rejects_fewer_than_72_bytes_and_keeps_bytes_beyond_the_entry() {
        assert_eq!(
            truncated(&[0; 71]),
            ParseError::Truncated {
                expected: 72,
                found: 71,
            }
        );
        assert_eq!(
            truncated(&[]),
            ParseError::Truncated {
                expected: 72,
                found: 0,
            }
        );

        let bytes: Vec<u8> = (0..80u8).collect();
        let entry = parsed(&bytes);
        assert_eq!(entry.unparsed.len(), 68);
        assert_eq!(
            entry.unparsed.get(entry.unparsed.len() - 8..),
            Some(&bytes[72..80])
        );
    }

    /// A zero `FILETIME` is kept as zero: whether it means "never opened" is a judgement for the
    /// collector, not something the parser decides by turning it into an absent value.
    #[test]
    fn parse_entry_keeps_a_zero_filetime_as_zero() {
        let entry = parsed(&[0; 72]);

        assert_eq!(entry.last_run_filetime, 0);
    }
}
