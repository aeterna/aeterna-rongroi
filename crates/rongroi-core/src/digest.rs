// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Path digests and the clock-change threshold (ADR 0081, sections 2 and 3).

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
