// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Windows Prefetch (`.pf`) files.
//!
//! Prefetch records that a program ran: its name, how many times, when it last ran, and the files it
//! loaded while running. Windows writes it to `%SystemRoot%\Prefetch`. Reading that folder — which
//! needs an elevated token — and deciding that an absent folder is `Unmeasured` rather than empty is
//! a collector's job; this module is handed the bytes of one file.
//!
//! # Compressed and uncompressed are both normal
//!
//! Windows 10 and 11 wrap the file in a `MAM\x04` header and compress the payload with
//! Xpress-Huffman; underneath is the classic `SCCA` structure. **An uncompressed `.pf` is a real
//! input, not a defect.** Prefetch can be switched off, and remnants of an older configuration or of
//! another machine can sit in the folder uncompressed. Both shapes go through [`parse`], which is
//! worth knowing for whoever writes the collector: finding a file without a `MAM` header is not a
//! reason to report anything as tampered.
//!
//! # Versions 30 and 31 only
//!
//! The SCCA version is the first four bytes of the decompressed payload: 17 (XP), 23 (Vista/7),
//! 26 (8.1), 30 (Windows 10), 31 (Windows 11). This project supports Windows 10 22H2 and Windows 11,
//! so versions 30 and 31 are read and every other version is a typed [`ParseError`]. A `.pf` from an
//! older Windows is a legitimate input that this parser cannot decode — never a panic, and never a
//! silently wrong parse, because the older `FileInformation` block has a different layout and reading
//! it with these offsets would produce plausible, wrong evidence.
//!
//! # The decompressor is a dependency, and its error type stops here
//!
//! MAM/Xpress-Huffman decompression and the SCCA layout come from the `prefetch-core` crate rather
//! than from code in this repository (ADR 0015). Nothing of that crate appears in a signature outside
//! this module: `parse` takes `&[u8]` and returns this crate's own [`PrefetchRecord`] and
//! [`ParseError`], exactly like [`crate::bam`] and [`crate::pca`]. `prefetch_core::PrefetchError` is
//! mapped here and never re-exported, so the rest of the codebase does not learn the name of a
//! third-party type and a later change of decompressor is a change to this file.
//!
//! # What this parser cannot keep
//!
//! [`crate::bam::BamEntry::unparsed_tail`] hands back every byte it did not decode. This module
//! cannot make that promise: `prefetch-core` returns a fixed set of fields, so bytes of the SCCA
//! payload it does not expose — the header beyond the executable name, the file-metrics array, the
//! directory strings — are not visible here to be kept. What is returned is what that crate decodes.
//! Raw `FILETIME` values are kept beside their converted timestamps, as BAM does, so nothing is lost
//! in the part this module does control.

use jiff::Timestamp;
use prefetch_core::{PrefetchError, PrefetchInfo};

use crate::error::ParseError;
use crate::filetime;

/// Smallest input [`parse`] can look at: a `MAM` signature and the declared decompressed size.
const MAM_HEADER_LEN: usize = 8;
/// Smallest decompressed payload that can hold an SCCA header and its `FileInformation` block.
const SCCA_HEADER_LEN: usize = 84;
/// Largest decompressed payload this parser will ask for, in bytes.
///
/// The declared size is a `u32` read from the file, and the decompressor reserves that much before it
/// decodes anything. A corrupt or hostile header declaring 4 GiB would therefore make the process
/// reserve 4 GiB, which is an allocation failure rather than a catchable error — and this crate
/// promises never to abort on any input. 16 MiB is far above any Prefetch file seen (the largest in
/// upstream corpus decompresses to 372 KiB, and the largest vendored here to 25 KiB) and far below a
/// size that could hurt.
const MAX_DECOMPRESSED_LEN: usize = 16 * 1024 * 1024;

/// One Windows Prefetch file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchRecord {
    /// SCCA format version: 30 on Windows 10, 31 on Windows 11.
    ///
    /// Kept rather than assumed, so a report can say which Windows wrote the file.
    pub scca_version: u32,
    /// The executable's base name as Prefetch stored it, which Windows upper-cases, e.g. `CMD.EXE`.
    ///
    /// **Content read from the machine.** A collector putting it in a report treats it like an
    /// observation's `path` field (CONVENTIONS.md §4).
    pub executable: String,
    /// How many times Prefetch recorded the program running.
    pub run_count: u32,
    /// Up to the eight most recent runs, newest first.
    pub last_runs: Vec<PrefetchRun>,
    /// The volumes the program touched.
    pub volumes: Vec<PrefetchVolume>,
    /// Full volume-relative paths of the files loaded during the recorded runs.
    ///
    /// **Content read from the machine, and normally hundreds of paths**, some of them under a user's
    /// profile. A collector that puts any of these in a report must redact them through
    /// `rongroi_core::view` exactly as it would an observation's `path` field (CONVENTIONS.md §4).
    pub loaded_files: Vec<String>,
}

/// One recorded run of the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefetchRun {
    /// The raw 64-bit `FILETIME` exactly as the file stored it.
    ///
    /// Kept beside [`Self::at`] so that a value the conversion cannot represent is still visible,
    /// as [`crate::bam::BamEntry::last_run_filetime`] is.
    pub filetime: u64,
    /// The same instant in UTC, through [`crate::filetime::to_timestamp`].
    ///
    /// `None` means the raw value does not name an instant this program can represent — a corrupt or
    /// hostile value, not an absent one.
    pub at: Option<Timestamp>,
}

/// One volume referenced by a Prefetch file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchVolume {
    /// The device path, e.g. `\VOLUME{01d68d85e0da1e22-b0e0e8ff}`.
    ///
    /// **Content read from the machine**; see [`PrefetchRecord::loaded_files`].
    pub device_path: String,
    /// The volume serial number, the 32-bit value Windows shows as eight hexadecimal digits.
    pub serial: u32,
    /// The raw 64-bit `FILETIME` of the volume's creation, exactly as the file stored it.
    pub created_filetime: u64,
    /// The same instant in UTC, through [`crate::filetime::to_timestamp`].
    pub created: Option<Timestamp>,
}

/// Parses one Prefetch file, MAM-compressed or not.
///
/// # Errors
///
/// [`ParseError::Truncated`] when the file is shorter than a `MAM` header, or when the decompressed
/// payload is too short to hold an SCCA header.
///
/// [`ParseError::Malformed`] when the file is not a Prefetch container (`signature`), when the
/// compressed payload does not decode (`compressed_payload`), when the declared decompressed size is
/// implausible (`decompressed_size`), when the SCCA version is not 30 or 31 (`scca_version`), or when
/// an offset inside the payload points past its end (`record`).
///
/// No error carries anything read from the file: `detail` is a fixed sentence in every case, so an
/// error message is safe to show in either mode (see [`ParseError::Malformed`]).
pub fn parse(bytes: &[u8]) -> Result<PrefetchRecord, ParseError> {
    reject_implausible_declared_size(bytes)?;

    // Decompression and SCCA parsing are called as two steps rather than through
    // `prefetch_core::parse`, so that a `Truncated` error can report the length that was actually
    // too short: the file's for a bad container, the decompressed payload's for a short payload.
    let scca = prefetch_core::decompress(bytes)
        .map_err(|error| to_parse_error(&error, MAM_HEADER_LEN, bytes.len()))?;
    let info = prefetch_core::parse_decompressed(&scca)
        .map_err(|error| to_parse_error(&error, SCCA_HEADER_LEN, scca.len()))?;

    Ok(record(info))
}

/// Refuses a `MAM` header whose declared decompressed size is larger than [`MAX_DECOMPRESSED_LEN`].
///
/// This runs before the decompressor because the decompressor reserves the declared size up front;
/// see [`MAX_DECOMPRESSED_LEN`]. An uncompressed file declares no size and is not affected, and a
/// file too short to hold the field is left to the decompressor to report as truncated.
fn reject_implausible_declared_size(bytes: &[u8]) -> Result<(), ParseError> {
    // An uncompressed payload carries the SCCA signature at offset 4 and no declared size. The
    // decompressor tests for that before it tests for `MAM`, so this must test in the same order.
    if bytes.get(SCCA_SIGNATURE_OFFSET..SCCA_SIGNATURE_OFFSET + 4) == Some(SCCA_SIGNATURE) {
        return Ok(());
    }
    // Only a MAM container has a declared size that could be implausible. Without this test, bytes
    // that are neither container would have those four bytes read as a size anyway — the corpus's
    // deliberately bad file, whose offset-4 signature is one letter away from `SCCA`, reads as a
    // declared 1 GiB — and a bad signature would be reported as an implausible size.
    if bytes.get(..MAM_SIGNATURE.len()) != Some(MAM_SIGNATURE) {
        return Ok(());
    }
    let Some(field) = bytes.get(4..MAM_HEADER_LEN) else {
        return Ok(());
    };
    let Ok(field) = <[u8; 4]>::try_from(field) else {
        return Ok(());
    };
    if u32::from_le_bytes(field) as usize > MAX_DECOMPRESSED_LEN {
        return Err(ParseError::Malformed {
            field: "decompressed_size",
            // The declared size is not quoted: it is read from the file, and `detail` carries nothing
            // that was.
            detail: "the header declares a decompressed size larger than any Prefetch file"
                .to_owned(),
        });
    }
    Ok(())
}

/// Offset of the `SCCA` signature inside an uncompressed payload.
const SCCA_SIGNATURE_OFFSET: usize = 4;
/// The signature of an uncompressed payload.
const SCCA_SIGNATURE: &[u8; 4] = b"SCCA";
/// The signature of a compressed container: `MAM` and the Xpress-Huffman compression byte, which is
/// the pair the decompressor requires before it reads a declared size.
const MAM_SIGNATURE: &[u8; 4] = b"MAM\x04";

/// Maps the decompressor's error into this crate's, which is where that type stops.
///
/// `minimum` and `found` belong to whichever step failed, so `Truncated` reports real lengths.
///
/// Every `detail` is a fixed sentence. Nothing read from the file is forwarded — not the SCCA version
/// number, and not the inner `xpress_huffman::Error`. That crate's `Display` happens today to be
/// three fixed strings with no file content in them, but forwarding it would make this crate's
/// promise — that an error is safe to show in either mode — depend on another crate's future wording.
///
/// The match is exhaustive on purpose: `PrefetchError` is not `#[non_exhaustive]`, so a variant added
/// upstream is a compile error here rather than a wildcard arm that silently mislabels it.
fn to_parse_error(error: &PrefetchError, minimum: usize, found: usize) -> ParseError {
    match error {
        PrefetchError::TooShort => ParseError::Truncated {
            expected: minimum,
            found,
        },
        PrefetchError::BadSignature => ParseError::Malformed {
            field: "signature",
            detail: "not a Prefetch file: no MAM container and no SCCA payload".to_owned(),
        },
        PrefetchError::Decompress(_) => ParseError::Malformed {
            field: "compressed_payload",
            detail: "the compressed payload does not decode as Xpress-Huffman".to_owned(),
        },
        PrefetchError::UnsupportedVersion(_) => ParseError::Malformed {
            field: "scca_version",
            detail:
                "unsupported SCCA version; this parser reads 30 (Windows 10) and 31 (Windows 11)"
                    .to_owned(),
        },
        PrefetchError::TruncatedRecord => ParseError::Malformed {
            field: "record",
            detail: "an offset or length in the payload points past its end".to_owned(),
        },
    }
}

/// Turns the decompressor's struct into ours, converting every `FILETIME` in one place.
fn record(info: PrefetchInfo) -> PrefetchRecord {
    PrefetchRecord {
        scca_version: info.version,
        executable: info.executable,
        run_count: info.run_count,
        last_runs: info.last_run_times.into_iter().map(run).collect(),
        volumes: info.volumes.into_iter().map(volume).collect(),
        loaded_files: info.filenames,
    }
}

fn run(filetime: i64) -> PrefetchRun {
    // `cast_unsigned` rather than a checked conversion: a `FILETIME` is unsigned, and the negative
    // `i64` this crate would hand back is the same 64 bits with the top one set. Keeping the bits is
    // what lets `filetime` decide the value names no representable instant, instead of this line
    // deciding it.
    let filetime = filetime.cast_unsigned();
    PrefetchRun {
        filetime,
        at: filetime::to_timestamp(filetime),
    }
}

fn volume(volume: prefetch_core::VolumeInfo) -> PrefetchVolume {
    let created_filetime = volume.creation_time.cast_unsigned();
    PrefetchVolume {
        device_path: volume.device_path,
        serial: volume.serial,
        created_filetime,
        created: filetime::to_timestamp(created_filetime),
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_DECOMPRESSED_LEN, parse};
    use crate::error::ParseError;
    use crate::filetime;

    const WIN10_V30: &[u8] =
        include_bytes!("../../../fixtures/prefetch/win10-compressed-v30-CMD.EXE-D269B812.pf");
    const WIN81_V26: &[u8] =
        include_bytes!("../../../fixtures/prefetch/win81-raw-v26-CMD.EXE-4A81B364.pf");
    const VISTA_V23: &[u8] =
        include_bytes!("../../../fixtures/prefetch/vista-raw-v23-CMD.EXE-89305D47.pf");
    const WINXP_V17: &[u8] =
        include_bytes!("../../../fixtures/prefetch/winxp-raw-v17-CMD.EXE-087B4001.pf");
    const BAD: &[u8] = include_bytes!("../../../fixtures/prefetch/bad-notAPrefetch.pf");

    #[test]
    fn a_windows_10_compressed_file_parses() {
        let record = parse(WIN10_V30).expect("the vendored Windows 10 fixture should parse");

        assert_eq!(record.scca_version, 30);
        assert_eq!(record.executable, "CMD.EXE");
        assert!(record.run_count > 0);
        assert!(!record.loaded_files.is_empty());
        assert!(!record.last_runs.is_empty());
        assert!(!record.volumes.is_empty());
    }

    /// An uncompressed `.pf` is a normal input: Prefetch can be switched off and remnants survive.
    /// The same bytes, decompressed once by hand, must parse to the same record.
    #[test]
    fn the_same_file_uncompressed_parses_to_the_same_record() {
        let scca = prefetch_core::decompress(WIN10_V30).expect("the fixture should decompress");

        assert_eq!(parse(&scca), parse(WIN10_V30));
        assert!(parse(&scca).is_ok());
    }

    /// Every timestamp comes from the one tested conversion, not from a second one written here.
    #[test]
    fn timestamps_come_from_the_shared_filetime_conversion() {
        let record = parse(WIN10_V30).expect("the vendored Windows 10 fixture should parse");

        for run in &record.last_runs {
            assert_eq!(run.at, filetime::to_timestamp(run.filetime));
            assert!(run.at.is_some(), "a real run time should convert");
        }
        for volume in &record.volumes {
            assert_eq!(
                volume.created,
                filetime::to_timestamp(volume.created_filetime)
            );
        }
    }

    #[test]
    fn an_unsupported_scca_version_is_a_typed_error() {
        for bytes in [WIN81_V26, VISTA_V23, WINXP_V17] {
            assert!(matches!(
                parse(bytes),
                Err(ParseError::Malformed {
                    field: "scca_version",
                    ..
                })
            ));
        }
    }

    #[test]
    fn the_deliberately_bad_file_is_a_typed_error() {
        assert!(matches!(
            parse(BAD),
            Err(ParseError::Malformed {
                field: "signature",
                ..
            })
        ));
    }

    #[test]
    fn a_zero_length_file_is_truncated() {
        assert_eq!(
            parse(&[]),
            Err(ParseError::Truncated {
                expected: 8,
                found: 0
            })
        );
    }

    #[test]
    fn a_truncated_mam_header_is_truncated() {
        assert_eq!(
            parse(&WIN10_V30[..5]),
            Err(ParseError::Truncated {
                expected: 8,
                found: 5
            })
        );
    }

    /// The declared size is reserved by the decompressor before it decodes anything, so an absurd one
    /// has to be refused here. Reaching the decompressor with this header would reserve 4 GiB, which
    /// is an allocation failure and not an error any caller could catch.
    #[test]
    fn an_implausible_declared_decompressed_size_is_refused_before_decompressing() {
        let mut bytes = b"MAM\x04".to_vec();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&[0x00; 64]);

        assert!(matches!(
            parse(&bytes),
            Err(ParseError::Malformed {
                field: "decompressed_size",
                ..
            })
        ));

        // One byte over the limit is refused; the limit itself is left to the decompressor.
        let mut at_limit = b"MAM\x04".to_vec();
        let over = u32::try_from(MAX_DECOMPRESSED_LEN + 1).expect("the limit fits in a u32");
        at_limit.extend_from_slice(&over.to_le_bytes());
        at_limit.extend_from_slice(&[0x00; 64]);
        assert!(matches!(
            parse(&at_limit),
            Err(ParseError::Malformed {
                field: "decompressed_size",
                ..
            })
        ));
    }

    /// A file that was cut short after the point where it would have been decompressed: the payload
    /// is a real SCCA prefix and too short for the header.
    #[test]
    fn a_body_truncated_after_decompression_is_truncated() {
        let scca = prefetch_core::decompress(WIN10_V30).expect("the fixture should decompress");

        assert_eq!(
            parse(&scca[..50]),
            Err(ParseError::Truncated {
                expected: 84,
                found: 50
            })
        );
    }

    /// A compressed payload whose bits are garbage while its container is intact. Whether the decoder
    /// rejects the stream or produces bytes that happen to parse is not the property under test —
    /// returning at all, rather than aborting, is.
    #[test]
    fn a_corrupt_compressed_stream_never_panics() {
        let mut bytes = WIN10_V30.to_vec();
        for byte in bytes.iter_mut().skip(8) {
            *byte = 0xFF;
        }

        let _ = parse(&bytes);
    }

    /// A `.pf` is read from a machine that may be hostile. No length may abort.
    #[test]
    fn no_length_of_a_real_file_panics() {
        for length in 0..WIN10_V30.len() {
            let _ = parse(&WIN10_V30[..length]);
        }
        for bytes in [WIN81_V26, VISTA_V23, WINXP_V17, BAD] {
            for length in (0..bytes.len()).step_by(97) {
                let _ = parse(&bytes[..length]);
            }
        }
    }

    /// The promise [`ParseError::Malformed`] makes: an error message is safe to show in either mode,
    /// so nothing read from the file may reach one. The fixtures' own strings are the test data.
    #[test]
    fn an_error_never_carries_anything_read_from_the_file() {
        let mut absurd = b"MAM\x04".to_vec();
        absurd.extend_from_slice(&u32::MAX.to_le_bytes());
        absurd.extend_from_slice(&[0x00; 64]);

        let attempts = [
            parse(WIN81_V26),
            parse(VISTA_V23),
            parse(WINXP_V17),
            parse(BAD),
            parse(&absurd),
            parse(&WIN10_V30[..5]),
        ];
        for attempt in attempts {
            let Err(error) = attempt else {
                continue;
            };
            let text = error.to_string().to_uppercase();
            for leaked in [
                "CMD",
                "DEVICE",
                "HARDDISKVOLUME",
                "SYSTEM32",
                ".DLL",
                ".EXE",
                "VOLUME{",
                "USERS",
            ] {
                assert!(
                    !text.contains(leaked),
                    "an error message leaked {leaked} from the file: {text}"
                );
            }
            // The version byte and the declared size are read from the file too, so no digit from
            // either may be quoted. `Truncated` carries lengths the caller already supplied, which is
            // why only `Malformed` is checked here.
            if matches!(error, ParseError::Malformed { .. }) {
                assert!(
                    !text.contains(|character: char| character.is_ascii_digit())
                        || text.contains("30 (WINDOWS 10)"),
                    "a malformed error quoted a number read from the file: {text}"
                );
            }
        }
    }

    /// The Windows 10 fixture's loaded-file list contains user profile paths. This pins that fact
    /// rather than wishing it away: it is why [`super::PrefetchRecord::loaded_files`] is documented as
    /// content a collector must redact through `rongroi_core::view` before it reaches a report, and
    /// `fixtures/prefetch/PROVENANCE.md` records why a file carrying them was vendored at all
    /// (every SCCA v30 file in that corpus carries the same account's paths — ADR 0015).
    #[test]
    fn the_windows_10_fixture_carries_user_profile_paths() {
        let record = parse(WIN10_V30).expect("the vendored Windows 10 fixture should parse");

        assert!(
            record
                .loaded_files
                .iter()
                .any(|path| path.to_uppercase().contains("\\USERS\\")),
            "the fixture is expected to carry profile paths; PROVENANCE.md describes them"
        );
    }

    /// The four older-version fixtures were picked from the corpus files that carry system paths
    /// only, so that the one account name in this folder is the one the Windows 10 file cannot avoid.
    #[test]
    fn the_older_version_fixtures_carry_no_user_profile_path() {
        for payload in [WIN81_V26, VISTA_V23, WINXP_V17, BAD] {
            let (pairs, _) = payload.as_chunks::<2>();
            let units: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
            let text = String::from_utf16_lossy(&units).to_uppercase();
            for profile in ["\\USERS\\", "\\DOCUMENTS AND SETTINGS\\", "\\HOME\\"] {
                assert!(
                    !text.contains(profile),
                    "a vendored fixture contains a user profile path: {profile}"
                );
            }
        }
    }
}
