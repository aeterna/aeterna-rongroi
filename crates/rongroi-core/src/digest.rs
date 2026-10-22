// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Path digests and the clock-change threshold (ADR 0081, sections 2 and 3).

use sha2::{Digest, Sha256};

/// The device prefix Windows puts in front of a volume-relative path, up to the volume number.
const VOLUME_PREFIX: &str = r"\Device\HarddiskVolume";

/// A clock step larger than this is reported as a clock change.
///
/// ADR 0081, section 3: this is a core constant, and changing it is a release decision (owner
/// decision 4), not a per-machine setting.
pub const CLOCK_CHANGE_THRESHOLD: jiff::SignedDuration = jiff::SignedDuration::from_secs(60);

/// Lowercase hex SHA-256 of `text`.
fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Puts a path into one spelling: `/` becomes `\` and ASCII letters are lowercased, so the same
/// file gives the same text whichever separator or case a report used.
fn normalise(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

/// SHA-256 digest of a drive-qualified path (`X:\...` or `X:/...`), normalised the way `normalise`
/// does: `/` becomes `\` and ASCII letters are lowercased.
///
/// Returns `None` for anything else, including UNC paths and bare file names.
///
/// What it hides: the path text, so a report can compare two sightings of one file without
/// printing the path. What it does not hide: anyone who already holds the path can compute the
/// same digest, and the same file gives the same digest in every report, so it is a pseudonym,
/// not a secret.
pub fn path_digest(path: &str) -> Option<String> {
    let [drive, colon, separator, ..] = path.as_bytes() else {
        return None;
    };
    if !drive.is_ascii_alphabetic() || *colon != b':' || !matches!(separator, b'\\' | b'/') {
        return None;
    }
    Some(sha256_hex(&normalise(path)))
}

/// SHA-256 digest of the part of a path after its volume, so the same file has one digest whether
/// a Windows API reported it as `X:\...` or as `\Device\HarddiskVolumeN\...`.
///
/// Accepts `X:\rest`, `X:/rest` and `\Device\HarddiskVolumeN\rest` (ASCII case ignored, `N` one or
/// more digits). Anything else gives `None`. The digest is over the normalised remainder, which
/// starts with `\`.
///
/// What it hides and what it does not are the same as [`path_digest`]: the in-volume path is
/// hidden from the report, but anyone holding that path can compute the digest, and it is stable
/// across reports.
pub fn volume_path_digest(path: &str) -> Option<String> {
    let remainder = strip_volume(path)?;
    Some(sha256_hex(&normalise(remainder)))
}

/// The path after its volume, or `None` when the path does not name a volume.
fn strip_volume(path: &str) -> Option<&str> {
    let is_drive_qualified = matches!(
        path.as_bytes(),
        [drive, b':', b'\\' | b'/', ..] if drive.is_ascii_alphabetic()
    );
    if is_drive_qualified {
        // The first two bytes are ASCII, so index 2 is a char boundary.
        return Some(&path[2..]);
    }
    // `get` returns `None` unless the prefix end is a char boundary, so the slice below cannot panic.
    let tail = match path.get(..VOLUME_PREFIX.len()) {
        Some(head) if head.eq_ignore_ascii_case(VOLUME_PREFIX) => &path[VOLUME_PREFIX.len()..],
        _ => return None,
    };
    let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let after = &tail[digits..];
    matches!(after.as_bytes().first(), Some(b'\\' | b'/')).then_some(after)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Lowercase hex SHA-256 of `text`, computed independently of the code under test.
    fn sha256_hex_of(text: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn path_digest_d1_normalises_case_and_separators() {
        assert_eq!(path_digest(r"C:\Tools\X.EXE"), path_digest("c:/tools/x.exe"));
        assert_eq!(
            path_digest(r"C:\Tools\X.EXE"),
            Some(sha256_hex_of(r"c:\tools\x.exe"))
        );
    }

    #[test]
    fn path_digest_d1_requires_a_drive_letter() {
        assert_eq!(path_digest(r"\Tools\x.exe"), None);
        assert_eq!(path_digest("x.exe"), None);
        assert_eq!(path_digest(r"\\server\share\x.exe"), None);
    }

    #[test]
    fn volume_path_digest_d2_drops_drive_or_device_prefix() {
        assert_eq!(
            volume_path_digest(r"\Device\HarddiskVolume5\Program Files\A\b.dll"),
            volume_path_digest(r"D:\program files\a\B.DLL")
        );
        assert_eq!(
            volume_path_digest(r"\Device\HarddiskVolume5\Program Files\A\b.dll"),
            Some(sha256_hex_of(r"\program files\a\b.dll"))
        );
    }

    #[test]
    fn volume_path_digest_d2_rejects_other_shapes() {
        assert_eq!(volume_path_digest(r"\Device\HarddiskVolumeX\a"), None);
        assert_eq!(volume_path_digest(r"\Device\Harddisk\a"), None);
        assert_eq!(volume_path_digest("a.dll"), None);
    }

    #[test]
    fn clock_change_threshold_d3_is_sixty_seconds() {
        assert_eq!(CLOCK_CHANGE_THRESHOLD, jiff::SignedDuration::from_secs(60));
    }
}
