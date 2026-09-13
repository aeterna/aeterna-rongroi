// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Windows-1252 (CP-1252) decoding, for the PCA text files.
//!
//! PCA writes ANSI text, which on a Western-configured Windows means CP-1252. A byte at or above
//! 0x80 is therefore an ordinary character, not invalid input: a player whose account name is
//! `José` produces a path with byte 0xE9 in it, and reading that file as UTF-8 would reject the line
//! and lose the evidence on it.
//!
//! The mapping is small enough to write down: 0x00–0x7F is ASCII, 0xA0–0xFF is Latin-1 (the code
//! point equals the byte), and only 0x80–0x9F needs a table, of 32 entries. That is cheaper than a
//! dependency on `encoding_rs` and keeps this crate at one dependency (ADR 0013).
//!
//! Microsoft leaves five of those 32 positions undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D). They are
//! decoded to the C1 control characters of the same value, which is what the WHATWG encoding
//! standard specifies and what browsers do. The alternative — a replacement character — would
//! destroy a byte, and this crate does not drop what it was given.

/// 0x80–0x9F. The rest of CP-1252 is computed, not tabulated.
const HIGH_CONTROLS: [char; 32] = [
    '\u{20ac}', // 0x80 euro sign
    '\u{81}',   // 0x81 undefined in CP-1252; kept as the C1 control of the same value
    '\u{201a}', // 0x82 single low-9 quotation mark
    '\u{192}',  // 0x83 latin small letter f with hook
    '\u{201e}', // 0x84 double low-9 quotation mark
    '\u{2026}', // 0x85 horizontal ellipsis
    '\u{2020}', // 0x86 dagger
    '\u{2021}', // 0x87 double dagger
    '\u{2c6}',  // 0x88 modifier letter circumflex accent
    '\u{2030}', // 0x89 per mille sign
    '\u{160}',  // 0x8a latin capital letter s with caron
    '\u{2039}', // 0x8b single left-pointing angle quotation mark
    '\u{152}',  // 0x8c latin capital ligature oe
    '\u{8d}',   // 0x8d undefined
    '\u{17d}',  // 0x8e latin capital letter z with caron
    '\u{8f}',   // 0x8f undefined
    '\u{90}',   // 0x90 undefined
    '\u{2018}', // 0x91 left single quotation mark
    '\u{2019}', // 0x92 right single quotation mark
    '\u{201c}', // 0x93 left double quotation mark
    '\u{201d}', // 0x94 right double quotation mark
    '\u{2022}', // 0x95 bullet
    '\u{2013}', // 0x96 en dash
    '\u{2014}', // 0x97 em dash
    '\u{2dc}',  // 0x98 small tilde
    '\u{2122}', // 0x99 trade mark sign
    '\u{161}',  // 0x9a latin small letter s with caron
    '\u{203a}', // 0x9b single right-pointing angle quotation mark
    '\u{153}',  // 0x9c latin small ligature oe
    '\u{9d}',   // 0x9d undefined
    '\u{17e}',  // 0x9e latin small letter z with caron
    '\u{178}',  // 0x9f latin capital letter y with diaeresis
];

/// Decodes CP-1252 bytes as text.
///
/// Total: every one of the 256 byte values maps to exactly one character, so this cannot fail and
/// cannot lose input. Line splitting happens on the bytes before this, so a decoded string never
/// needs to be searched for line endings.
pub(crate) fn decode(bytes: &[u8]) -> String {
    bytes.iter().copied().map(decode_byte).collect()
}

fn decode_byte(byte: u8) -> char {
    match byte {
        // The one range whose characters are not its byte values.
        0x80..=0x9f => {
            HIGH_CONTROLS
                .get(usize::from(byte) - 0x80)
                .copied()
                // Unreachable: the table holds exactly the 32 entries this range needs. Were it ever
                // the wrong length, the byte's own value is the honest fallback -- this must not
                // reach for a replacement character, which would destroy what was read.
                .unwrap_or(char::from(byte))
        }
        // 0x00-0x7F is ASCII and 0xA0-0xFF is Latin-1: in both, the code point is the byte value.
        _ => char::from(byte),
    }
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn ascii_passes_through_unchanged() {
        assert_eq!(
            decode(b"C:\\Users\\alex\\game.exe"),
            "C:\\Users\\alex\\game.exe"
        );
    }

    #[test]
    fn the_thirty_two_byte_table_is_applied() {
        assert_eq!(decode(&[0x80]), "\u{20ac}"); // euro sign
        assert_eq!(decode(&[0x93, 0x94]), "\u{201c}\u{201d}"); // curly double quotes
        assert_eq!(decode(&[0x99]), "\u{2122}"); // trade mark sign
        assert_eq!(decode(&[0x9f]), "\u{178}"); // capital y with diaeresis
    }

    #[test]
    fn the_latin_one_range_is_the_byte_value_itself() {
        assert_eq!(decode(&[0xe9]), "\u{e9}"); // small e with acute
        assert_eq!(decode(&[0xa0]), "\u{a0}"); // no-break space
        assert_eq!(decode(&[0xff]), "\u{ff}"); // small y with diaeresis
    }

    /// The five positions Microsoft leaves undefined keep their byte value instead of becoming a
    /// replacement character. Nothing read is destroyed, and the decoding stays reversible.
    #[test]
    fn the_undefined_positions_keep_their_value() {
        assert_eq!(
            decode(&[0x81, 0x8d, 0x8f, 0x90, 0x9d]),
            "\u{81}\u{8d}\u{8f}\u{90}\u{9d}"
        );
    }

    /// Every byte decodes to exactly one character: nothing is dropped, nothing is merged.
    #[test]
    fn all_two_hundred_and_fifty_six_bytes_decode_to_one_character_each() {
        let every_byte: Vec<u8> = (0..=u8::MAX).collect();

        let decoded = decode(&every_byte);

        assert_eq!(decoded.chars().count(), 256);
    }

    /// The point of having this at all: bytes that UTF-8 rejects are ordinary CP-1252 text.
    #[test]
    fn input_that_is_not_valid_utf8_still_decodes() {
        let bytes = [0xe9, b'A'];

        assert!(String::from_utf8(bytes.to_vec()).is_err());
        assert_eq!(decode(&bytes), "\u{e9}A");
    }

    /// A NUL is a character here, not a terminator. A UTF-16 file read by mistake is full of them,
    /// and its lines must survive as far as the line parser, which is what rejects them.
    #[test]
    fn a_nul_byte_is_a_character_not_the_end_of_the_string() {
        assert_eq!(decode(&[b'A', 0x00, b'B']).chars().count(), 3);
    }
}
