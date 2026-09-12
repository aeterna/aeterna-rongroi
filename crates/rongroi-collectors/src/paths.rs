// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a collector may say about a path an artifact spelled.
//!
//! Two artifacts record the full path of a program that ran — PCA in a text line, BAM in the name of
//! a registry value — and both have to answer the same two questions: which single field a rule can
//! match on, and whether this path is a shape SS-mode redaction can reach. They live here rather than
//! in one collector because two collectors answering the same question in two wordings is two things
//! a rule author has to learn. `pca` wrote both first (ADR 0020) and `bam` uses them unchanged
//! (ADR 0023).

/// What a path was replaced with when it is not a shape SS-mode redaction can reach.
pub const UNREDACTABLE_FORM: &str = "unredactable_form";

/// The last segment of a Windows path, lower-cased.
///
/// Lower-cased so that `Cheat.exe` and `cheat.exe` reach a report, and a rule author, as one string.
/// It is no longer what makes a rule match: ADR 0025 made `match` fold ASCII case, so a rule naming
/// either spelling matches either. `path` is left exactly as the artifact spelled it, which is what
/// CONVENTIONS.md defines it as.
pub fn file_name(path: &str) -> Option<String> {
    let name = path.rsplit(['\\', '/']).next()?;
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

/// Whether a path starts `X:\` or `X:/`.
///
/// This is the only shape `rongroi_core::view::redact_user_paths` was written for, and it is
/// deliberately narrower than what that function can reach: a path this refuses is withheld, and
/// erring toward withholding is the direction that cannot leak a user name.
pub fn is_drive_rooted(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_the_last_segment_lower_cased() {
        assert_eq!(
            file_name(r"C:\Users\alex\Game.EXE").as_deref(),
            Some("game.exe")
        );
        assert_eq!(
            file_name(r"\\nas\share\Tool.exe").as_deref(),
            Some("tool.exe")
        );
        assert_eq!(file_name("bare.exe").as_deref(), Some("bare.exe"));
        assert_eq!(file_name(r"C:\Users\alex\"), None);
    }

    /// The device path is the shape BAM is expected to write and the shape that walks straight past
    /// `redact_user_paths`, so it is named here rather than left to a collector's own test.
    #[test]
    fn only_a_drive_rooted_path_is_emitted() {
        assert!(is_drive_rooted(r"C:\Users\alex\x.exe"));
        assert!(is_drive_rooted("d:/users/alex/x.exe"));
        assert!(!is_drive_rooted(r"\\nas\share\x.exe"));
        assert!(!is_drive_rooted(
            r"\Device\HarddiskVolume3\Users\alex\x.exe"
        ));
        assert!(!is_drive_rooted(r"\??\C:\Users\alex\x.exe"));
        assert!(!is_drive_rooted("C:"));
        assert!(!is_drive_rooted(""));
    }
}
