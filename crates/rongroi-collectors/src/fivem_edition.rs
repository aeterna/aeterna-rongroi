// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Which of `FiveM`'s two program folders a path an artifact recorded is below (ADR 0062, section 2).
//!
//! Both editions name their client `FiveM.exe`, so a name cannot say which one ran. A path can: Legacy
//! runs from `%LOCALAPPDATA%\FiveM\…` and Enhanced from `%LOCALAPPDATA%\FiveM for GTAV Enhanced\…`, the
//! two program folders `fivem_dir` already reads (ADR 0036, ADR 0061). `process`, `bam` and `prefetch`
//! each hold such a path and each emits one word from it, `fivem_edition: legacy | enhanced`, and never
//! a path it does not already emit (ADR 0062, section 6). The match lives here so that the three answer
//! it in one wording.
//!
//! The match is made on the path's segments, **as a path below a profile**: some root, a profile folder,
//! then `AppData\Local\` and one of the two folder names as whole segments, then at least one more
//! segment. It does not depend on how the path begins, so the three spellings these artifacts use all
//! reach it — a drive letter (`C:\Users\…`, a process image), a device path
//! (`\Device\HarddiskVolumeN\Users\…`, BAM) and a volume path (`\VOLUME{…}\USERS\…`, Prefetch's string
//! table). Windows compares names without ASCII case and Prefetch upper-cases them, so this does too.
//!
//! The word says where a file of that name ran from, not which program it was (ADR 0034). A path below
//! neither folder has no edition, and the field is then omitted.

use crate::fivem_dir::{ENHANCED_PROGRAM_RELATIVE_PATH, LEGACY_PROGRAM_RELATIVE_PATH};

/// The observation field that carries the edition.
pub const FIELD: &str = "fivem_edition";

/// The folder below a profile that `%LOCALAPPDATA%` names, as two segments.
const LOCAL_APP_DATA_SEGMENTS: [&str; 2] = ["AppData", "Local"];

/// One of `FiveM`'s two editions, as a program folder says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FivemEdition {
    /// `FiveM` for GTA V Legacy: below `%LOCALAPPDATA%\FiveM\`.
    Legacy,
    /// `FiveM` for GTA V Enhanced: below `%LOCALAPPDATA%\FiveM for GTAV Enhanced\`.
    Enhanced,
}

impl FivemEdition {
    /// The word a report carries.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Enhanced => "enhanced",
        }
    }

    /// The edition whose program folder is exactly this segment, compared without ASCII case.
    fn of_folder(segment: &str) -> Option<Self> {
        if segment.eq_ignore_ascii_case(LEGACY_PROGRAM_RELATIVE_PATH) {
            Some(Self::Legacy)
        } else if segment.eq_ignore_ascii_case(ENHANCED_PROGRAM_RELATIVE_PATH) {
            Some(Self::Enhanced)
        } else {
            None
        }
    }
}

/// The edition whose program folder `path` is below, or `None` when it is below neither.
///
/// Only the first `AppData` segment is considered, and it must have a profile folder before it and the
/// path's root before that. A path holding a `.` or `..` segment, or an empty segment after `AppData`,
/// is refused: such a spelling may name a file outside the folder it appears to be below, and this
/// program does not attribute a path to a folder it only appears to be below (as `paths::is_refused_form`
/// refuses those forms for reading).
pub fn of_path(path: &str) -> Option<FivemEdition> {
    let segments: Vec<&str> = path.split(['\\', '/']).collect();
    if segments
        .iter()
        .any(|segment| crate::paths::is_unusable_segment(segment))
    {
        return None;
    }
    let app_data = segments
        .iter()
        .position(|segment| segment.eq_ignore_ascii_case(LOCAL_APP_DATA_SEGMENTS[0]))?;
    // A root and a profile folder before `AppData`: `C:` and `alex` in `C:\Users\alex\AppData`, or
    // `HarddiskVolume3` and `alex` in the device form. The profile folder is never empty.
    if app_data < 2 || segments[app_data - 1].is_empty() {
        return None;
    }
    let below = &segments[app_data + 1..];
    // `Local`, the program folder, and at least one segment below it, none of them empty.
    if below.len() < 3 || below.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    if !below[0].eq_ignore_ascii_case(LOCAL_APP_DATA_SEGMENTS[1]) {
        return None;
    }
    FivemEdition::of_folder(below[1])
}

/// The edition of the program a Prefetch file records, from the executable's own entry in the file's
/// string table (ADR 0062, owner decision 6 of 2026-10-02).
///
/// The executable's own entry is the entry whose last segment is the executable's name, compared
/// without ASCII case. Every such entry must be below the same edition's folder; when there is none, or
/// they disagree, or one is below neither, there is no edition. Any other entry — a library the program
/// loaded from one of `FiveM`'s folders — says nothing about where the program itself ran from, and is
/// not read. Prefetch keeps a name of at most 29 characters, so a longer one matches no entry and has no
/// edition.
pub fn of_prefetch(executable: &str, loaded_files: &[String]) -> Option<FivemEdition> {
    let executable = executable.trim();
    if executable.is_empty() {
        return None;
    }
    let mut edition = None;
    for entry in loaded_files {
        let Some(name) = entry.rsplit(['\\', '/']).next() else {
            continue;
        };
        if !name.eq_ignore_ascii_case(executable) {
            continue;
        }
        let this = of_path(entry)?;
        if edition.is_some_and(|seen| seen != this) {
            return None;
        }
        edition = Some(this);
    }
    edition
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_editions_folder_gives_its_word() {
        assert_eq!(
            of_path(r"C:\Users\alex\AppData\Local\FiveM\FiveM.exe"),
            Some(FivemEdition::Legacy)
        );
        assert_eq!(
            of_path(
                r"C:\Users\alex\AppData\Local\FiveM\FiveM.app\data\cache\subprocess\FiveM_b2802_GTAProcess.exe"
            ),
            Some(FivemEdition::Legacy)
        );
        assert_eq!(
            of_path(r"C:\Users\alex\AppData\Local\FiveM for GTAV Enhanced\FiveM.exe"),
            Some(FivemEdition::Enhanced)
        );
        assert_eq!(FivemEdition::Legacy.as_str(), "legacy");
        assert_eq!(FivemEdition::Enhanced.as_str(), "enhanced");
    }

    #[test]
    fn case_does_not_matter() {
        assert_eq!(
            of_path(r"c:\users\alex\appdata\local\fivem\fivem.app\fivem.exe"),
            Some(FivemEdition::Legacy)
        );
        assert_eq!(
            of_path(r"C:\USERS\ALEX\APPDATA\LOCAL\FIVEM FOR GTAV ENHANCED\FIVEM.EXE"),
            Some(FivemEdition::Enhanced)
        );
    }

    /// BAM spells a path from the volume's device, and Prefetch from the volume's GUID. Neither has a
    /// drive letter, and both are still below a profile.
    #[test]
    fn device_and_volume_paths_are_matched_like_a_drive_path() {
        assert_eq!(
            of_path(r"\Device\HarddiskVolume3\Users\alex\AppData\Local\FiveM\FiveM.exe"),
            Some(FivemEdition::Legacy)
        );
        assert_eq!(
            of_path(
                r"\Device\HarddiskVolume3\Users\alex\AppData\Local\FiveM for GTAV Enhanced\FiveM.exe"
            ),
            Some(FivemEdition::Enhanced)
        );
        assert_eq!(
            of_path(
                r"\VOLUME{01d00000000000000-0000abcd}\USERS\ALEX\APPDATA\LOCAL\FIVEM\FIVEM.APP\FIVEM.EXE"
            ),
            Some(FivemEdition::Legacy)
        );
        assert_eq!(
            of_path(r"\\?\C:\Users\alex\AppData\Local\FiveM for GTAV Enhanced\FiveM.exe"),
            Some(FivemEdition::Enhanced)
        );
    }

    #[test]
    fn a_path_outside_both_folders_has_no_edition() {
        for outside in [
            r"C:\Users\alex\Downloads\FiveM.exe",
            r"C:\Program Files\Rockstar Games\Grand Theft Auto V Enhanced\PlayGTAV.exe",
            r"C:\Users\alex\AppData\Roaming\FiveM for GTAV Enhanced\FiveM.exe",
            r"\Device\HarddiskVolume3\Windows\System32\cmd.exe",
            r"C:\Users\alex\AppData\Local\Temp\FiveM\FiveM.exe",
            // `AppData` below a temporary folder: only the first `AppData` is the profile's.
            r"C:\Users\alex\AppData\Local\Temp\AppData\Local\FiveM\FiveM.exe",
            "FiveM.exe",
            "",
        ] {
            assert_eq!(of_path(outside), None, "{outside}");
        }
    }

    /// A folder whose name only begins like one of `FiveM`'s, or holds it, is another folder.
    #[test]
    fn a_look_alike_folder_name_has_no_edition() {
        for look_alike in [
            r"C:\Users\alex\AppData\Local\FiveM2\FiveM.exe",
            r"C:\Users\alex\AppData\Local\FiveM.old\FiveM.exe",
            r"C:\Users\alex\AppData\Local\FiveM for GTAV Enhanced (2)\FiveM.exe",
            r"C:\Users\alex\AppData\Local\FiveM for GTAV\FiveM.exe",
            r"C:\Users\alex\AppData\Local\My FiveM\FiveM.exe",
            r"C:\Users\alex\AppData\LocalLow\FiveM\FiveM.exe",
        ] {
            assert_eq!(of_path(look_alike), None, "{look_alike}");
        }
    }

    /// Not a file below the folder: the folder itself, or a spelling that walks out of it.
    #[test]
    fn the_folder_itself_and_a_walking_spelling_have_no_edition() {
        for refused in [
            r"C:\Users\alex\AppData\Local\FiveM",
            r"C:\Users\alex\AppData\Local\FiveM\",
            r"C:\Users\alex\AppData\Local\FiveM\..\Tool.exe",
            r"C:\Users\alex\AppData\Local\FiveM\.\FiveM.exe",
            r"C:\Users\alex\AppData\Local\FiveM\\FiveM.exe",
            // No profile folder between the root and `AppData`.
            r"C:\AppData\Local\FiveM\FiveM.exe",
            r"\AppData\Local\FiveM\FiveM.exe",
        ] {
            assert_eq!(of_path(refused), None, "{refused}");
        }
    }

    fn table(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_owned()).collect()
    }

    const VOLUME: &str = r"\VOLUME{01d00000000000000-0000abcd}";

    #[test]
    fn prefetch_reads_the_executables_own_entry() {
        let legacy = table(&[
            &format!(r"{VOLUME}\WINDOWS\SYSTEM32\NTDLL.DLL"),
            &format!(r"{VOLUME}\USERS\ALEX\APPDATA\LOCAL\FIVEM\FIVEM.APP\FIVEM.EXE"),
        ]);
        assert_eq!(
            of_prefetch("FIVEM.EXE", &legacy),
            Some(FivemEdition::Legacy)
        );
        let enhanced = table(&[&format!(
            r"{VOLUME}\USERS\ALEX\APPDATA\LOCAL\FIVEM FOR GTAV ENHANCED\FIVEM.EXE"
        )]);
        assert_eq!(
            of_prefetch("FIVEM.EXE", &enhanced),
            Some(FivemEdition::Enhanced)
        );
        // The name in the header and the entry differ only in case.
        assert_eq!(
            of_prefetch("FiveM.exe", &enhanced),
            Some(FivemEdition::Enhanced)
        );
    }

    /// A program that loaded a library from one of `FiveM`'s folders did not run from it.
    #[test]
    fn prefetch_ignores_every_entry_but_the_executables_own() {
        let files = table(&[
            &format!(r"{VOLUME}\PROGRAM FILES\ROCKSTAR GAMES\GTA V\PLAYGTAV.EXE"),
            &format!(r"{VOLUME}\USERS\ALEX\APPDATA\LOCAL\FIVEM\FIVEM.APP\CITIZEN.DLL"),
        ]);
        assert_eq!(of_prefetch("PLAYGTAV.EXE", &files), None);
    }

    #[test]
    fn prefetch_with_no_own_entry_or_disagreeing_entries_has_no_edition() {
        let legacy = format!(r"{VOLUME}\USERS\ALEX\APPDATA\LOCAL\FIVEM\FIVEM.EXE");
        let enhanced =
            format!(r"{VOLUME}\USERS\ALEX\APPDATA\LOCAL\FIVEM FOR GTAV ENHANCED\FIVEM.EXE");
        let outside = format!(r"{VOLUME}\USERS\ALEX\DOWNLOADS\FIVEM.EXE");
        assert_eq!(of_prefetch("FIVEM.EXE", &[]), None);
        assert_eq!(of_prefetch("", &table(&[&legacy])), None);
        assert_eq!(
            of_prefetch("FIVEM.EXE", &table(&[&legacy, &enhanced])),
            None
        );
        assert_eq!(of_prefetch("FIVEM.EXE", &table(&[&legacy, &outside])), None);
        // Twice the same edition is still that edition.
        assert_eq!(
            of_prefetch("FIVEM.EXE", &table(&[&legacy, &legacy])),
            Some(FivemEdition::Legacy)
        );
        // A name Prefetch cut short matches no entry.
        assert_eq!(
            of_prefetch("FIVEM_B2802_GTAPROCESS.E", &table(&[&legacy])),
            None
        );
    }
}
