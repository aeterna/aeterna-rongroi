// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Program Compatibility Assistant (PCA) text files.
//!
//! `%WinDir%\appcompat\pca\PcaAppLaunchDic.txt` records executables PCA saw launched, and
//! `PcaGeneralDb0.txt` / `PcaGeneralDb1.txt` record more about them.
//!
//! # Windows 11 22H2 and later only
//!
//! These files do not exist on Windows 10 at all. Their absence there is not a failure and not an
//! empty result: it is a machine that cannot be measured this way, and the collector reports
//! `Unmeasured { not_on_this_os }` (AGENTS.md hard rule 4). It is stated here so that the next
//! person does not go looking for the artifact on a Windows 10 test machine and conclude the parser
//! is broken.
//!
//! # Encoding
//!
//! ANSI — CP-1252 in a Western configuration — with CRLF line endings. Not UTF-8 and not UTF-16. A
//! byte at or above 0x80 is a valid character, not invalid input; see [`crate::cp1252`].
//!
//! # One bad line never loses the file
//!
//! Both parsers return a [`PcaFile`]: the records that parsed, plus a [`RejectedLine`] for each one
//! that did not, with its line number and the reason. A tampered or truncated artifact is exactly
//! when the surviving lines matter most, so a single malformed line is accounted for rather than
//! thrown, and the whole file is refused only when it is not this kind of file at all (ADR 0013).
//!
//! # What is unverified here
//!
//! `PcaGeneralDb0.txt`'s layout is reverse-engineered rather than documented, so its fields are
//! **not named**: [`PcaGeneralEntry`] hands back the `|`-delimited fields in order and assigns no
//! meaning to any position, for the same reason BAM's trailing bytes are kept unnamed. Naming them
//! is a later change, once a real file on a current build establishes what they are. The delimiter
//! and timestamp shape of `PcaAppLaunchDic.txt` come from public write-ups and this repository has
//! no corpus to confirm them against.

use jiff::Timestamp;
use jiff::civil::DateTime;
use jiff::tz::Offset;

use crate::cp1252;
use crate::error::ParseError;

/// What one PCA file yielded: the records that parsed, and an account of the lines that did not.
///
/// `rejected` being empty is the only thing that says a file was intact. A caller that looks only at
/// `entries` sees a shorter file, not a damaged one, which is why the two are returned together
/// rather than the lines that failed being dropped (ADR 0013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcaFile<T> {
    /// The records that parsed, in the order the file had them.
    pub entries: Vec<T>,
    /// One entry for each line that did not parse, in the order the file had them.
    pub rejected: Vec<RejectedLine>,
}

/// A line that did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedLine {
    /// Line number, counting from 1 and counting every line including blank ones, so that it means
    /// the same thing as the line number a text editor shows.
    pub line_number: usize,
    /// Why the line did not parse.
    pub reason: ParseError,
    /// The line as it was decoded, so that a person can see what the parser could not read.
    ///
    /// **This is content read from the machine and normally contains a full user path.** A collector
    /// that puts it in a report must redact it through `rongroi_core::view` exactly as it would an
    /// observation's `path` field (CONVENTIONS.md §4). Reporting only `line_number` and `reason` is
    /// usually enough and carries nothing personal.
    pub text: String,
}

/// One line of `PcaAppLaunchDic.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcaLaunchEntry {
    /// The executable's full path, exactly as the line spelled it.
    pub path: String,
    /// When PCA recorded that executable running, in UTC.
    pub last_run: Timestamp,
}

/// One line of `PcaGeneralDb0.txt` or `PcaGeneralDb1.txt`, as its fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcaGeneralEntry {
    /// Every `|`-delimited field of the line, in order, decoded from CP-1252 and otherwise
    /// untouched.
    ///
    /// No position is given a name: this file's layout is reverse-engineered, and a field named on a
    /// guess would put that guess into evidence a server admin is asked to trust. A line with more
    /// or fewer fields than any write-up describes is kept whole rather than rejected or padded.
    pub fields: Vec<String>,
}

/// Parses `PcaAppLaunchDic.txt`, whose lines are `<full executable path>|<UTC timestamp>`.
///
/// A line that does not parse is recorded in [`PcaFile::rejected`]; it does not fail the file.
///
/// # Errors
///
/// [`ParseError::Malformed`] with field `encoding` when the input begins with a UTF-16 byte order
/// mark, which means this is not a PCA text file at all.
pub fn parse_app_launch_dic(bytes: &[u8]) -> Result<PcaFile<PcaLaunchEntry>, ParseError> {
    parse_lines(bytes, parse_launch_line)
}

/// Parses `PcaGeneralDb0.txt` / `PcaGeneralDb1.txt` into their `|`-delimited fields, naming none of
/// them.
///
/// A line that does not parse is recorded in [`PcaFile::rejected`]; it does not fail the file.
///
/// # Errors
///
/// [`ParseError::Malformed`] with field `encoding` when the input begins with a UTF-16 byte order
/// mark, which means this is not a PCA text file at all.
pub fn parse_general_db(bytes: &[u8]) -> Result<PcaFile<PcaGeneralEntry>, ParseError> {
    parse_lines(bytes, parse_general_line)
}

fn parse_lines<T>(
    bytes: &[u8],
    parse_line: fn(&str) -> Result<T, ParseError>,
) -> Result<PcaFile<T>, ParseError> {
    reject_utf16(bytes)?;

    let mut entries = Vec::new();
    let mut rejected = Vec::new();

    for (index, line) in split_lines(bytes).enumerate() {
        let text = cp1252::decode(line);
        // A blank line is neither a record nor an error. It still consumed a line number, so that a
        // reported number matches the file.
        if text.is_empty() {
            continue;
        }
        match parse_line(&text) {
            Ok(entry) => entries.push(entry),
            Err(reason) => rejected.push(RejectedLine {
                line_number: index + 1,
                reason,
                text,
            }),
        }
    }

    Ok(PcaFile { entries, rejected })
}

/// The one thing that fails a whole file.
///
/// A byte order mark is positive evidence that the bytes are UTF-16, so nothing here is readable and
/// saying so once is more use than several hundred identical rejections. Without a mark there is no
/// such evidence, and the file is read as asked: a real CP-1252 file with a few stray NUL bytes in
/// it must not be thrown away on a guess about its encoding.
fn reject_utf16(bytes: &[u8]) -> Result<(), ParseError> {
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return Err(ParseError::Malformed {
            field: "encoding",
            detail: "input begins with a UTF-16 byte order mark; PCA files are CP-1252 text"
                .to_owned(),
        });
    }
    Ok(())
}

/// Splits on LF and drops one trailing CR, so CRLF files, a file whose last line has no line ending,
/// and a file written with bare LFs all read the same way.
fn split_lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|&byte| byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
}

fn parse_launch_line(line: &str) -> Result<PcaLaunchEntry, ParseError> {
    // A Windows path cannot contain '|', so the first one is the delimiter.
    let Some((path, timestamp)) = line.split_once('|') else {
        return Err(ParseError::Malformed {
            field: "delimiter",
            detail: "expected <path>|<timestamp>".to_owned(),
        });
    };
    if path.is_empty() {
        return Err(ParseError::Malformed {
            field: "path",
            detail: "empty".to_owned(),
        });
    }

    Ok(PcaLaunchEntry {
        path: path.to_owned(),
        last_run: parse_timestamp(timestamp)?,
    })
}

fn parse_general_line(line: &str) -> Result<PcaGeneralEntry, ParseError> {
    let fields: Vec<String> = line.split('|').map(str::to_owned).collect();
    // The field count is deliberately not checked beyond this: more or fewer fields than any
    // write-up describes is a newer Windows build, not a broken line.
    if fields.len() < 2 {
        return Err(ParseError::Malformed {
            field: "delimiter",
            detail: "expected at least one '|' field separator".to_owned(),
        });
    }

    Ok(PcaGeneralEntry { fields })
}

fn parse_timestamp(text: &str) -> Result<Timestamp, ParseError> {
    parse_timestamp_parts(text).ok_or(ParseError::Malformed {
        field: "timestamp",
        detail: "expected YYYY-MM-DD HH:MM:SS in UTC".to_owned(),
    })
}

/// `None` for anything that is not exactly the expected shape. jiff does the calendar validation, so
/// an impossible date such as `2026-13-45` is rejected here rather than silently normalised.
fn parse_timestamp_parts(text: &str) -> Option<Timestamp> {
    let (date, time) = text.split_once(' ')?;
    let [year, month, day] = three_numbers(date, '-')?;
    let [hour, minute, second] = three_numbers(time, ':')?;

    let datetime = DateTime::new(
        i16::try_from(year).ok()?,
        i8::try_from(month).ok()?,
        i8::try_from(day).ok()?,
        i8::try_from(hour).ok()?,
        i8::try_from(minute).ok()?,
        i8::try_from(second).ok()?,
        0,
    )
    .ok()?;

    // The file's timestamps are UTC, so this is a fixed offset: no time zone database is consulted
    // and the machine's own time zone cannot change the answer.
    Offset::UTC.to_timestamp(datetime).ok()
}

/// Exactly three runs of digits separated by `separator`, and nothing else.
fn three_numbers(text: &str, separator: char) -> Option<[u32; 3]> {
    let mut parts = text.split(separator);
    let numbers = [
        digits(parts.next()?)?,
        digits(parts.next()?)?,
        digits(parts.next()?)?,
    ];
    if parts.next().is_some() {
        return None;
    }
    Some(numbers)
}

/// A run of ASCII digits and nothing else: `str::parse` alone would also accept `+7`, and
/// surrounding whitespace would hide a field that is not the shape it looks like.
fn digits(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{PcaFile, PcaGeneralEntry, PcaLaunchEntry, parse_app_launch_dic, parse_general_db};
    use crate::error::ParseError;

    /// Joins lines with CRLF, including after the last one, as Windows writes them.
    fn crlf_file(lines: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for line in lines {
            bytes.extend_from_slice(line);
            bytes.extend_from_slice(b"\r\n");
        }
        bytes
    }

    fn launch(bytes: &[u8]) -> PcaFile<PcaLaunchEntry> {
        match parse_app_launch_dic(bytes) {
            Ok(file) => file,
            Err(error) => panic!("expected the file to parse: {error}"),
        }
    }

    fn general(bytes: &[u8]) -> PcaFile<PcaGeneralEntry> {
        match parse_general_db(bytes) {
            Ok(file) => file,
            Err(error) => panic!("expected the file to parse: {error}"),
        }
    }

    fn utf16le(text: &str, with_bom: bool) -> Vec<u8> {
        let mut bytes = if with_bom {
            vec![0xFF, 0xFE]
        } else {
            Vec::new()
        };
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn a_normal_app_launch_file() {
        let bytes = crlf_file(&[
            b"C:\\Users\\alex\\Downloads\\game.exe|2026-09-12 10:23:46",
            b"C:\\Program Files\\FiveM\\FiveM.exe|2026-09-11 22:05:01",
            b"C:\\Windows\\System32\\notepad.exe|2026-01-02 03:04:05",
        ]);

        let file = launch(&bytes);

        assert!(file.rejected.is_empty());
        assert_eq!(file.entries.len(), 3);
        assert_eq!(file.entries[0].path, "C:\\Users\\alex\\Downloads\\game.exe");
        assert_eq!(file.entries[0].last_run.to_string(), "2026-09-12T10:23:46Z");
        assert_eq!(file.entries[2].last_run.to_string(), "2026-01-02T03:04:05Z");
    }

    /// A path with an accented letter, written as the single CP-1252 byte Windows would store
    /// rather than as UTF-8. Reading this file as UTF-8 would reject the line and lose it.
    #[test]
    fn a_path_with_a_cp1252_byte_above_7f_decodes() {
        let mut line = b"C:\\Users\\jos".to_vec();
        line.push(0xE9); // small e with acute, in CP-1252
        line.extend_from_slice(b"\\game.exe|2026-09-12 10:23:46");

        let file = launch(&crlf_file(&[&line]));

        assert!(file.rejected.is_empty());
        assert_eq!(file.entries[0].path, "C:\\Users\\jos\u{e9}\\game.exe");
    }

    /// The headline requirement: the surviving lines survive, and the bad one is accounted for.
    #[test]
    fn one_line_with_no_delimiter_does_not_lose_the_file() {
        let bytes = crlf_file(&[
            b"C:\\Users\\alex\\first.exe|2026-09-12 10:23:46",
            b"this line has no delimiter at all",
            b"C:\\Users\\alex\\third.exe|2026-09-12 11:00:00",
        ]);

        let file = launch(&bytes);

        assert_eq!(file.entries.len(), 2);
        assert_eq!(file.entries[0].path, "C:\\Users\\alex\\first.exe");
        assert_eq!(file.entries[1].path, "C:\\Users\\alex\\third.exe");
        assert_eq!(file.rejected.len(), 1);
        assert_eq!(file.rejected[0].line_number, 2);
        assert_eq!(file.rejected[0].text, "this line has no delimiter at all");
        assert!(matches!(
            file.rejected[0].reason,
            ParseError::Malformed {
                field: "delimiter",
                ..
            }
        ));
    }

    #[test]
    fn a_line_with_an_unparsable_timestamp_is_rejected_and_the_rest_survive() {
        let bytes = crlf_file(&[
            b"C:\\Users\\alex\\first.exe|not a timestamp",
            b"C:\\Users\\alex\\second.exe|2026-13-45 99:99:99",
            b"C:\\Users\\alex\\third.exe|2026-09-12 11:00:00",
        ]);

        let file = launch(&bytes);

        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].path, "C:\\Users\\alex\\third.exe");
        assert_eq!(file.rejected.len(), 2);
        for rejected in &file.rejected {
            assert!(matches!(
                rejected.reason,
                ParseError::Malformed {
                    field: "timestamp",
                    ..
                }
            ));
        }
        assert_eq!(file.rejected[0].line_number, 1);
        assert_eq!(file.rejected[1].line_number, 2);
    }

    #[test]
    fn an_empty_path_is_rejected() {
        let file = launch(&crlf_file(&[b"|2026-09-12 10:23:46"]));

        assert!(file.entries.is_empty());
        assert!(matches!(
            file.rejected[0].reason,
            ParseError::Malformed { field: "path", .. }
        ));
    }

    #[test]
    fn an_empty_file_has_no_entries_and_no_rejections() {
        let file = launch(b"");

        assert!(file.entries.is_empty());
        assert!(file.rejected.is_empty());
        assert!(parse_general_db(b"").is_ok());
    }

    /// A file that was truncated mid-write, or simply never got its final CRLF.
    #[test]
    fn the_last_line_parses_without_a_trailing_crlf() {
        let bytes = b"C:\\Users\\alex\\first.exe|2026-09-12 10:23:46\r\nC:\\Users\\alex\\last.exe|2026-09-12 11:00:00";

        let file = launch(bytes);

        assert!(file.rejected.is_empty());
        assert_eq!(file.entries.len(), 2);
        assert_eq!(file.entries[1].path, "C:\\Users\\alex\\last.exe");
    }

    /// Blank lines are neither records nor errors, but they still count for line numbering, so a
    /// reported number matches what a text editor shows.
    #[test]
    fn blank_lines_are_skipped_but_still_counted() {
        let bytes = crlf_file(&[
            b"",
            b"C:\\Users\\alex\\first.exe|2026-09-12 10:23:46",
            b"",
            b"no delimiter here",
        ]);

        let file = launch(&bytes);

        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.rejected.len(), 1);
        assert_eq!(file.rejected[0].line_number, 4);
    }

    #[test]
    fn a_general_db_line_with_more_fields_than_expected_is_kept_whole() {
        let bytes = crlf_file(&[
            b"2026-09-12 10:23:46|C:\\Users\\alex\\game.exe|Game|1.2.3.4|Example Ltd|extra|more",
        ]);

        let file = general(&bytes);

        assert!(file.rejected.is_empty());
        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].fields.len(), 7);
        assert_eq!(file.entries[0].fields[1], "C:\\Users\\alex\\game.exe");
        assert_eq!(file.entries[0].fields[6], "more");
    }

    #[test]
    fn a_general_db_line_with_fewer_fields_than_expected_is_kept_whole() {
        let file = general(&crlf_file(&[
            b"2026-09-12 10:23:46|C:\\Users\\alex\\game.exe",
        ]));

        assert!(file.rejected.is_empty());
        assert_eq!(file.entries[0].fields.len(), 2);
    }

    /// A general-database line is a delimited record; one field is not a record of this kind.
    #[test]
    fn a_general_db_line_with_no_delimiter_is_rejected_without_losing_the_file() {
        let bytes = crlf_file(&[
            b"2026-09-12 10:23:46|C:\\Users\\alex\\game.exe",
            b"nodelimiter",
        ]);

        let file = general(&bytes);

        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.rejected.len(), 1);
        assert_eq!(file.rejected[0].line_number, 2);
    }

    /// A UTF-16 file is not this artifact. Saying so once is more use to a collector than several
    /// hundred rejected lines, and nothing is lost by refusing it: none of it was readable.
    #[test]
    fn a_utf16_file_with_a_byte_order_mark_is_refused_as_a_whole() {
        let bytes = utf16le("C:\\Users\\alex\\game.exe|2026-09-12 10:23:46\r\n", true);

        assert!(matches!(
            parse_app_launch_dic(&bytes),
            Err(ParseError::Malformed {
                field: "encoding",
                ..
            })
        ));
        assert!(matches!(
            parse_general_db(&bytes),
            Err(ParseError::Malformed {
                field: "encoding",
                ..
            })
        ));
    }

    /// Without a byte order mark there is nothing that proves the encoding, so the file is read as
    /// asked and its lines fail one by one. That is the behaviour that keeps a real CP-1252 file
    /// with a few stray NUL bytes in it from being thrown away whole.
    #[test]
    fn utf16_without_a_byte_order_mark_rejects_lines_rather_than_the_file() {
        let bytes = utf16le("C:\\Users\\alex\\game.exe|2026-09-12 10:23:46\r\n", false);

        let file = launch(&bytes);

        assert!(file.entries.is_empty());
        assert!(!file.rejected.is_empty());
    }

    /// These files are read from a machine that may be hostile. No input may abort.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let inputs: [&[u8]; 8] = [
            b"",
            b"|",
            b"||||",
            b"\r\n\r\n\r\n",
            b"\x00\x00\x00",
            b"C:\\a.exe|2026-09-12 10:23:46\x00trailing",
            &[0xFF, 0xFE],
            &[0xFE, 0xFF, 0x00, 0x41],
        ];
        for input in inputs {
            let _ = parse_app_launch_dic(input);
            let _ = parse_general_db(input);
        }

        let every_byte: Vec<u8> = (0..=u8::MAX).cycle().take(2048).collect();
        for length in (0..every_byte.len()).step_by(7) {
            let _ = parse_app_launch_dic(&every_byte[..length]);
            let _ = parse_general_db(&every_byte[..length]);
        }
    }
}
