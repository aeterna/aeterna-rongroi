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

/// One program path a source recorded, with the newest time that source gave it.
///
/// `recorded_files` orders its reads by distance from the newest `FiveM` record, so each source hands
/// back the time it already read for the path rather than letting the collector read the artifact a
/// second time.
#[derive(Debug, Clone)]
pub(crate) struct RecordedPath {
    /// The path exactly as the source spelled it.
    pub(crate) path: String,
    /// The newest instant this source recorded for the path, or `None` when it gave none.
    pub(crate) at: Option<jiff::Timestamp>,
}

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
/// This is the shape `rongroi_core::view::redact_profile_paths` was first written for, and it is
/// deliberately narrower than what that function reaches (ADR 0049): a path this refuses is withheld,
/// and erring toward withholding is the direction that cannot leak a user name.
pub fn is_drive_rooted(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

#[cfg(test)]
mod tests {
    use rongroi_host::{DriveKind, DriveMap, DriveMapEntry};

    use super::*;

    /// One invented letter for a drive map. Its device and serial never come from a real machine.
    fn drive(letter: char, device: &str, serial: u32, kind: DriveKind) -> DriveMapEntry {
        DriveMapEntry {
            letter,
            device: device.to_owned(),
            serial,
            kind,
        }
    }

    fn map_of(entries: Vec<DriveMapEntry>) -> DriveMap {
        DriveMap { entries }
    }

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
    /// `redact_profile_paths`, so it is named here rather than left to a collector's own test.
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

    /// A BAM device path is emitted as the fixed letter that has that device at scan time (ADR 0087
    /// sections 2 and 3).
    #[test]
    fn a_device_path_maps_to_the_letter_with_that_device() {
        let map = map_of(vec![
            drive(
                'C',
                r"\Device\HarddiskVolume7",
                0x0bad_f00d,
                DriveKind::Fixed,
            ),
            drive(
                'D',
                r"\Device\HarddiskVolume12",
                0x1a2b_3c4d,
                DriveKind::Fixed,
            ),
        ]);
        assert_eq!(
            map_device_path(
                &map,
                r"\Device\HarddiskVolume7\Users\fixtureuser\AppData\Local\Temp\tool.exe"
            )
            .as_deref(),
            Some(r"C:\Users\fixtureuser\AppData\Local\Temp\tool.exe")
        );
        assert_eq!(
            map_device_path(&map, r"\Device\HarddiskVolume12\Games\GTA5.exe").as_deref(),
            Some(r"D:\Games\GTA5.exe")
        );
    }

    /// The device name is compared without ASCII case, and only the letter is rewritten.
    #[test]
    fn a_device_path_matches_its_device_without_ascii_case() {
        let map = map_of(vec![drive(
            'E',
            r"\Device\HarddiskVolume3",
            0x2b3c_4d5e,
            DriveKind::Fixed,
        )]);
        assert_eq!(
            map_device_path(
                &map,
                r"\DEVICE\harddiskvolume3\USERS\FIXTUREUSER\AppData\Local\Temp\tool.exe"
            )
            .as_deref(),
            Some(r"E:\USERS\FIXTUREUSER\AppData\Local\Temp\tool.exe")
        );
    }

    /// The whole volume number is compared, so `Volume1` never matches `Volume12`.
    #[test]
    fn a_volume_number_is_compared_whole() {
        let one = map_of(vec![drive(
            'C',
            r"\Device\HarddiskVolume1",
            0x0bad_f00d,
            DriveKind::Fixed,
        )]);
        assert_eq!(
            map_device_path(&one, r"\Device\HarddiskVolume1\x.exe").as_deref(),
            Some(r"C:\x.exe")
        );
        assert_eq!(
            map_device_path(&one, r"\Device\HarddiskVolume12\x.exe"),
            None
        );

        let twelve = map_of(vec![drive(
            'D',
            r"\Device\HarddiskVolume12",
            0x1a2b_3c4d,
            DriveKind::Fixed,
        )]);
        assert_eq!(
            map_device_path(&twelve, r"\Device\HarddiskVolume1\x.exe"),
            None
        );
        assert_eq!(
            map_device_path(&twelve, r"\Device\HarddiskVolume12\x.exe").as_deref(),
            Some(r"D:\x.exe")
        );
    }

    /// Two letters naming one device answer no letter, because either would be a guess (ADR 0087
    /// section 2).
    #[test]
    fn two_letters_with_one_device_map_nothing() {
        let map = map_of(vec![
            drive(
                'C',
                r"\Device\HarddiskVolume7",
                0x0bad_f00d,
                DriveKind::Fixed,
            ),
            drive(
                'D',
                r"\Device\HarddiskVolume7",
                0x1a2b_3c4d,
                DriveKind::Fixed,
            ),
        ]);
        assert_eq!(
            map_device_path(
                &map,
                r"\Device\HarddiskVolume7\Users\fixtureuser\AppData\Local\Temp\tool.exe"
            ),
            None
        );
    }

    /// A Prefetch volume path is mapped by the serial Windows wrote in it, not by the creation time
    /// beside it (ADR 0087 section 2).
    #[test]
    fn a_volume_path_maps_by_its_serial() {
        let map = map_of(vec![
            drive(
                'C',
                r"\Device\HarddiskVolume7",
                0x0bad_f00d,
                DriveKind::Fixed,
            ),
            drive(
                'D',
                r"\Device\HarddiskVolume12",
                0x1a2b_3c4d,
                DriveKind::Fixed,
            ),
        ]);
        assert_eq!(
            map_device_path(
                &map,
                r"\VOLUME{2026-01-01T00:00:00.0000000+00:00-1a2b3c4d}\Users\fixtureuser\AppData\Local\Temp\tool.exe"
            )
            .as_deref(),
            Some(r"D:\Users\fixtureuser\AppData\Local\Temp\tool.exe")
        );
    }

    /// A cloned disk gives two letters with one serial, and neither is chosen.
    #[test]
    fn two_letters_with_one_serial_map_nothing() {
        let map = map_of(vec![
            drive(
                'C',
                r"\Device\HarddiskVolume7",
                0x1a2b_3c4d,
                DriveKind::Fixed,
            ),
            drive(
                'D',
                r"\Device\HarddiskVolume12",
                0x1a2b_3c4d,
                DriveKind::Fixed,
            ),
        ]);
        assert_eq!(
            map_device_path(
                &map,
                r"\VOLUME{2026-01-01T00:00:00.0000000+00:00-1a2b3c4d}\Users\fixtureuser\AppData\Local\Temp\tool.exe"
            ),
            None
        );
    }

    /// Only eight lowercase hex digits are the serial `Host::file_id` gives (ADR 0087 section 2).
    #[test]
    fn a_serial_of_another_length_maps_nothing() {
        let map = map_of(vec![drive(
            'C',
            r"\Device\HarddiskVolume7",
            0x1a2b_3c4d,
            DriveKind::Fixed,
        )]);
        for path in [
            r"\VOLUME{2026-01-01T00:00:00.0000000+00:00-1a2b3c}\x.exe",
            r"\VOLUME{2026-01-01T00:00:00.0000000+00:00-1a2b3c4de}\x.exe",
            r"\VOLUME{2026-01-01T00:00:00.0000000+00:00-}\x.exe",
            r"\VOLUME{2026-01-01T00:00:00.0000000+00:00}\x.exe",
        ] {
            assert_eq!(map_device_path(&map, path), None, "{path}");
        }
    }

    /// A path of any other shape is not a device path the map can turn into a letter.
    #[test]
    fn a_path_of_another_shape_maps_nothing() {
        let map = map_of(vec![drive(
            'C',
            r"\Device\HarddiskVolume7",
            0x1a2b_3c4d,
            DriveKind::Fixed,
        )]);
        for path in [
            r"C:\Users\fixtureuser\x.exe",
            r"\\nas\share\x.exe",
            r"\??\C:\Users\fixtureuser\x.exe",
            r"\Device\HarddiskVolume\Users\fixtureuser\x.exe",
            r"\Device\HarddiskVolume7x\Users\fixtureuser\x.exe",
            r"\Device\OtherVolume7\Users\fixtureuser\x.exe",
            "",
        ] {
            assert_eq!(map_device_path(&map, path), None, "{path}");
        }
    }

    /// BAM maps a device path only on a fixed letter: a removable number can name another volume
    /// later, and any other kind is not a fixed disk either (ADR 0087 section 3).
    #[test]
    fn a_device_path_on_a_letter_that_is_not_fixed_maps_nothing() {
        for kind in [DriveKind::Removable, DriveKind::Other] {
            let map = map_of(vec![drive(
                'F',
                r"\Device\HarddiskVolume9",
                0x1a2b_3c4d,
                kind,
            )]);
            assert_eq!(
                map_device_path(
                    &map,
                    r"\Device\HarddiskVolume9\Users\fixtureuser\AppData\Local\Temp\tool.exe"
                ),
                None,
                "{kind:?}"
            );
        }
    }
}
