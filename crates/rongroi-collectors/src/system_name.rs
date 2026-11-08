// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Whether a Windows program's name ran outside the folders Windows keeps it in (ADR 0094,
//! section 4).
//!
//! Some program takes a Windows program's name so a person scrolling a process list does not stop at
//! it (MITRE ATT&CK T1036.005). The table holds the names Windows puts in `System32`, `SysWOW64` or
//! `%SystemRoot%` itself, measured on a real machine (ADR 0094, section 4). A path is compared below
//! `%SystemRoot%`, which the caller passes in, and the four servicing folders; any other folder
//! answers `true` and an expected or servicing one `false`. Comparison ignores ASCII case, because
//! Windows reports `C:\WINDOWS\Explorer.EXE` itself. The folder comes from a path the source already
//! holds and is never emitted; a name outside the table, or an unreadable folder, gives no value
//! (ADR 0010).

use rongroi_host::is_unusable_segment;

/// The observation field that carries whether a table name ran outside its expected folders.
pub const FIELD: &str = "system_name_elsewhere";

/// One folder a name is expected in, as segments below `%SystemRoot%`; the empty slice is
/// `%SystemRoot%` itself.
type Folder = &'static [&'static str];

/// The folder Windows keeps a 64-bit program in.
const SYSTEM32: Folder = &["System32"];
/// The folder Windows keeps a 32-bit program in.
const SYSWOW64: Folder = &["SysWOW64"];
/// `%SystemRoot%` itself, where `explorer.exe` runs.
const WINDOWS_ROOT: Folder = &[];

/// The servicing folders below `%SystemRoot%` (ADR 0094, section 4).
const SERVICING_BELOW_SYSTEM_ROOT: [Folder; 2] = [&["WinSxS"], &["SoftwareDistribution"]];
/// The servicing folders at a drive's root (ADR 0094, section 4).
const SERVICING_BELOW_DRIVE_ROOT: [Folder; 2] = [&["$WINDOWS.~BT"], &["$WinREAgent"]];

/// One name in the measured table and the folders Windows keeps it in.
struct NameEntry {
    /// The program's file name, as ADR 0094 section 4 spells it.
    name: &'static str,
    /// Every folder the measurement found it in, below `%SystemRoot%`.
    folders: &'static [Folder],
}

/// The table measured in ADR 0094 section 4. A name added here needs a new measurement and a line
/// in that ADR's amendments.
const NAMES: [NameEntry; 13] = [
    NameEntry {
        name: "svchost.exe",
        folders: &[SYSTEM32, SYSWOW64],
    },
    NameEntry {
        name: "explorer.exe",
        folders: &[WINDOWS_ROOT, SYSWOW64],
    },
    NameEntry {
        name: "lsass.exe",
        folders: &[SYSTEM32],
    },
    NameEntry {
        name: "csrss.exe",
        folders: &[SYSTEM32],
    },
    NameEntry {
        name: "smss.exe",
        folders: &[SYSTEM32],
    },
    NameEntry {
        name: "wininit.exe",
        folders: &[SYSTEM32],
    },
    NameEntry {
        name: "winlogon.exe",
        folders: &[SYSTEM32],
    },
    NameEntry {
        name: "services.exe",
        folders: &[SYSTEM32],
    },
    NameEntry {
        name: "dwm.exe",
        folders: &[SYSTEM32],
    },
    NameEntry {
        name: "conhost.exe",
        folders: &[SYSTEM32],
    },
    NameEntry {
        name: "taskhostw.exe",
        folders: &[SYSTEM32],
    },
    NameEntry {
        name: "RuntimeBroker.exe",
        folders: &[SYSTEM32],
    },
    NameEntry {
        name: "spoolsv.exe",
        folders: &[SYSTEM32],
    },
];

/// The folders a table name is expected in, or `None` when the name is not in the table.
fn expected_folders(name: &str) -> Option<&'static [Folder]> {
    NAMES
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(name))
        .map(|entry| entry.folders)
}

/// Whether `folder` is exactly `root` followed by `relative`, compared without ASCII case.
fn folder_is(folder: &[&str], root: &[&str], relative: Folder) -> bool {
    folder.len() == root.len() + relative.len() && folder_is_below_root(folder, root, relative)
}

/// Whether `folder` is below `root` followed by `relative`, compared without ASCII case.
fn folder_is_below_root(folder: &[&str], root: &[&str], relative: Folder) -> bool {
    folder.len() >= root.len() + relative.len()
        && root
            .iter()
            .chain(relative.iter())
            .zip(folder)
            .all(|(&expected, &seen)| expected.eq_ignore_ascii_case(seen))
}

/// Whether `folder` is below one of the servicing folders under `%SystemRoot%`.
fn servicing_below_root(folder: &[&str], root: &[&str]) -> bool {
    SERVICING_BELOW_SYSTEM_ROOT
        .iter()
        .any(|relative| folder_is_below_root(folder, root, relative))
}

/// Whether `folder` is below one of the servicing folders at a drive's root.
fn servicing_below_drive_root(folder: &[&str]) -> bool {
    SERVICING_BELOW_DRIVE_ROOT
        .iter()
        .any(|relative| folder_is_below_root(folder, &[], relative))
}

/// Whether `folder` is an expected or servicing folder for `name`, or `None` when the name is not
/// in the table. Folders below `%SystemRoot%` only match on its drive; the drive-root servicing
/// folders are not tied to a drive letter.
fn folder_is_inside(
    name: &str,
    folder: &[&str],
    root: &[&str],
    on_system_drive: bool,
) -> Option<bool> {
    let folders = expected_folders(name)?;
    let under_root = on_system_drive
        && (folders
            .iter()
            .any(|relative| folder_is(folder, root, relative))
            || servicing_below_root(folder, root));
    Some(under_root || servicing_below_drive_root(folder))
}

/// The drive letter and the non-empty segments below its root of a drive-letter path, or `None`
/// when the path is not one or holds a spelling this program refuses as a folder.
fn drive_segments(path: &str) -> Option<(u8, Vec<&str>)> {
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }
    let drive = bytes[0].to_ascii_uppercase();
    let rest = &path[2..];
    if !(rest.starts_with('\\') || rest.starts_with('/')) {
        return None;
    }
    let mut segments = rest.split(['\\', '/']);
    if segments.next() != Some("") {
        return None;
    }
    let segments: Vec<&str> = segments.collect();
    if segments
        .iter()
        .any(|segment| segment.is_empty() || is_unusable_segment(segment))
    {
        return None;
    }
    Some((drive, segments))
}

/// The folder part of a Prefetch string-table entry below its `\VOLUME{…}` prefix, or `None` when
/// the entry does not have that form or holds a spelling this program refuses as a folder.
fn volume_folder(entry: &str) -> Option<Vec<&str>> {
    let rest = entry
        .strip_prefix('\\')
        .or_else(|| entry.strip_prefix('/'))?;
    let mut segments = rest.split(['\\', '/']);
    let volume = segments.next()?;
    let is_volume = volume
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("VOLUME{"))
        && volume.ends_with('}');
    if !is_volume {
        return None;
    }
    let segments: Vec<&str> = segments.collect();
    if segments.is_empty()
        || segments
            .iter()
            .any(|segment| segment.is_empty() || is_unusable_segment(segment))
    {
        return None;
    }
    let (_, folder) = segments.split_last()?;
    Some(folder.to_vec())
}

/// Whether the program at the drive-letter `path` is a table name outside the folders Windows
/// keeps it in, or `None` when its name is not in the table or its folder cannot be read.
///
/// `system_root` is `%SystemRoot%` as the scanned machine spells it, never an assumed `C:\Windows`.
pub fn of_path(path: &str, system_root: &str) -> Option<bool> {
    let (drive, segments) = drive_segments(path)?;
    let (name, folder) = segments.split_last()?;
    let (root_drive, root) = drive_segments(system_root.trim_end_matches(['\\', '/']))?;
    let inside = folder_is_inside(name, folder, &root, drive == root_drive)?;
    Some(!inside)
}

/// Whether the program a Prefetch file records is a table name outside the folders Windows keeps it
/// in, or `None` when its name is not in the table, its folder cannot be read, or its entries
/// disagree.
///
/// The executable's own entry is the string-table entry whose last segment is the executable's
/// name, compared without ASCII case, as `fivem_edition::of_prefetch` reads it. Every such entry
/// must give the same answer; when they disagree there is no value. The entry's folder is the part
/// below its `\VOLUME{…}` prefix, compared with `system_root` minus its drive letter. The volume
/// prefix is not mapped to a drive letter, so the entry is compared as if it were on
/// `%SystemRoot%`'s drive (a copy under another volume's `\Windows\System32` reads `false`). The
/// entry itself is never emitted.
pub fn of_prefetch(executable: &str, loaded_files: &[String], system_root: &str) -> Option<bool> {
    let executable = executable.trim();
    if executable.is_empty() {
        return None;
    }
    let (_, root) = drive_segments(system_root.trim_end_matches(['\\', '/']))?;
    let mut elsewhere = None;
    for entry in loaded_files {
        let Some(name) = entry.rsplit(['\\', '/']).next() else {
            continue;
        };
        if !name.eq_ignore_ascii_case(executable) {
            continue;
        }
        let folder = volume_folder(entry)?;
        let inside = folder_is_inside(name, &folder, &root, true)?;
        let this = !inside;
        if elsewhere.is_some_and(|seen| seen != this) {
            return None;
        }
        elsewhere = Some(this);
    }
    elsewhere
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM_ROOT: &str = r"C:\Windows";

    fn with_root(system_root: &str, cases: &[(&str, Option<bool>)]) {
        for &(path, expected) in cases {
            assert_eq!(of_path(path, system_root), expected, "{path}");
        }
    }

    fn paths(cases: &[(&str, Option<bool>)]) {
        with_root(SYSTEM_ROOT, cases);
    }

    fn folders_text(folders: &[Folder]) -> String {
        folders
            .iter()
            .map(|folder| {
                if folder.is_empty() {
                    "%SystemRoot%".to_owned()
                } else {
                    folder.join("\\")
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The table, exactly as ADR 0094 section 4 measured it.
    #[test]
    fn the_table_is_the_one_adr_0094_section_4_measured() {
        let expected = [
            ("svchost.exe", "System32, SysWOW64"),
            ("explorer.exe", "%SystemRoot%, SysWOW64"),
            ("lsass.exe", "System32"),
            ("csrss.exe", "System32"),
            ("smss.exe", "System32"),
            ("wininit.exe", "System32"),
            ("winlogon.exe", "System32"),
            ("services.exe", "System32"),
            ("dwm.exe", "System32"),
            ("conhost.exe", "System32"),
            ("taskhostw.exe", "System32"),
            ("RuntimeBroker.exe", "System32"),
            ("spoolsv.exe", "System32"),
        ];
        assert_eq!(NAMES.len(), expected.len());
        for (name, folders) in expected {
            let entry = NAMES
                .iter()
                .find(|entry| entry.name == name)
                .expect("the table names it");
            assert_eq!(folders_text(entry.folders), folders, "{name}");
        }
    }

    /// A servicing folder never makes a table name "elsewhere", at any depth, for any name.
    #[test]
    fn the_servicing_folders_are_not_elsewhere() {
        paths(&[
            (r"C:\Windows\WinSxS\svchost.exe", Some(false)),
            (r"C:\Windows\SoftwareDistribution\lsass.exe", Some(false)),
            (r"C:\$WINDOWS.~BT\smss.exe", Some(false)),
            (r"C:\$WinREAgent\Sources\wininit.exe", Some(false)),
        ]);
    }

    /// An expected folder is matched exactly. A folder below it, or one that only starts with its
    /// name, is elsewhere.
    #[test]
    fn an_expected_folder_matches_exactly_not_by_prefix() {
        paths(&[
            (r"C:\Windows\Temp\explorer.exe", Some(true)),
            (r"C:\Windows\System32\drivers\svchost.exe", Some(true)),
        ]);
    }

    /// A servicing folder is matched by whole segment: `WinSxSX` is not `WinSxS`.
    #[test]
    fn a_servicing_folder_matches_by_whole_segment() {
        paths(&[
            (r"C:\Windows\WinSxSX\svchost.exe", Some(true)),
            (r"C:\$WINDOWS.~BTX\smss.exe", Some(true)),
        ]);
    }

    /// `%SystemRoot%` written with a trailing backslash is the same root, not an unreadable path.
    #[test]
    fn a_system_root_with_a_trailing_backslash_is_the_same_root() {
        assert_eq!(
            of_path(r"C:\Windows\System32\svchost.exe", r"C:\Windows\"),
            Some(false)
        );
    }

    /// Pins current behaviour: the Prefetch volume prefix is not mapped to a drive letter, so an
    /// entry under any `\VOLUME{…}` is compared as if it were on `%SystemRoot%`'s drive. A copy under
    /// another volume's `\Windows\System32` therefore reads `false`, not "elsewhere".
    #[test]
    fn prefetch_takes_a_different_volume_to_be_the_system_drive() {
        const OTHER_VOLUME: &str = r"\VOLUME{01d00000000000000-0000ffff}";
        let system32 = format!(r"{OTHER_VOLUME}\WINDOWS\SYSTEM32\SVCHOST.EXE");
        let elsewhere = format!(r"{OTHER_VOLUME}\PROGRAMDATA\X\SVCHOST.EXE");
        assert_eq!(
            of_prefetch("svchost.exe", &table(&[&system32]), SYSTEM_ROOT),
            Some(false)
        );
        assert_eq!(
            of_prefetch("svchost.exe", &table(&[&elsewhere]), SYSTEM_ROOT),
            Some(true)
        );
    }

    /// Windows reports these paths in mixed case; the comparison ignores ASCII case.
    #[test]
    fn case_does_not_matter() {
        paths(&[
            (r"C:\WINDOWS\Explorer.EXE", Some(false)),
            (r"c:\windows\system32\SVCHOST.EXE", Some(false)),
            (r"C:\WINDOWS\SYSTEM32\RUNTIMEBROKER.EXE", Some(false)),
            (r"C:\windows\programdata\x\Svchost.Exe", Some(true)),
        ]);
    }

    /// Only the two names the measurement found in `SysWOW64` are expected there.
    #[test]
    fn syswow64_is_expected_only_for_svchost_and_explorer() {
        paths(&[
            (r"C:\Windows\SysWOW64\svchost.exe", Some(false)),
            (r"C:\Windows\SysWOW64\explorer.exe", Some(false)),
        ]);
        let names = "lsass.exe csrss.exe smss.exe wininit.exe winlogon.exe services.exe dwm.exe \
                     conhost.exe taskhostw.exe RuntimeBroker.exe spoolsv.exe";
        for name in names.split(' ') {
            let path = format!(r"C:\Windows\SysWOW64\{name}");
            assert_eq!(of_path(&path, SYSTEM_ROOT), Some(true), "{name}");
        }
    }

    /// A table name anywhere else is `true`, whatever its case or depth.
    #[test]
    fn a_table_name_outside_windows_folders_is_elsewhere() {
        paths(&[
            (r"C:\ProgramData\x\svchost.exe", Some(true)),
            (r"C:\ProgramData\x\Explorer.EXE", Some(true)),
        ]);
    }

    #[test]
    fn a_name_not_in_the_table_is_omitted() {
        paths(&[
            (r"C:\Windows\System32\cmd.exe", None),
            (r"C:\ProgramData\x\notepad.exe", None),
        ]);
    }

    #[test]
    fn an_empty_relative_or_folderness_path_is_omitted() {
        paths(&[
            ("", None),
            ("svchost.exe", None),
            (r"Windows\System32\svchost.exe", None),
            (r"C:svchost.exe", None),
            (r"C:\", None),
            (r"C:\Windows\System32\", None),
            (r"C:\Windows\\System32\svchost.exe", None),
            (r"C:\Windows\System32\..\svchost.exe", None),
        ]);
    }

    #[test]
    fn system_root_is_wherever_the_machine_put_it() {
        let d = r"D:\Windows";
        let on_d = [
            (r"D:\Windows\System32\svchost.exe", Some(false)),
            (r"D:\WINDOWS\Explorer.EXE", Some(false)),
            (r"D:\Windows\SysWOW64\explorer.exe", Some(false)),
            (r"D:\$WINDOWS.~BT\svchost.exe", Some(false)),
            // The same folders on C: are elsewhere when Windows is on D:.
            (r"C:\Windows\System32\svchost.exe", Some(true)),
            (r"C:\Windows\explorer.exe", Some(true)),
        ];
        with_root(d, &on_d);
        // And D:'s folders are elsewhere when Windows is on C:.
        paths(&[(r"D:\Windows\System32\svchost.exe", Some(true))]);
    }

    const VOLUME: &str = r"\VOLUME{01d00000000000000-0000abcd}";

    fn table(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_owned()).collect()
    }

    #[test]
    fn prefetch_reads_the_executables_own_entry() {
        let system32 = format!(r"{VOLUME}\WINDOWS\SYSTEM32\SVCHOST.EXE");
        let elsewhere = format!(r"{VOLUME}\PROGRAMDATA\X\SVCHOST.EXE");
        assert_eq!(
            of_prefetch("SVCHOST.EXE", &table(&[&system32]), SYSTEM_ROOT),
            Some(false)
        );
        assert_eq!(
            of_prefetch("svchost.exe", &table(&[&elsewhere]), SYSTEM_ROOT),
            Some(true)
        );
        // The name in the header and the entry differ only in case.
        assert_eq!(
            of_prefetch("Svchost.Exe", &table(&[&system32]), SYSTEM_ROOT),
            Some(false)
        );
    }

    #[test]
    fn prefetch_omits_disagreeing_entries() {
        let system32 = format!(r"{VOLUME}\WINDOWS\SYSTEM32\SVCHOST.EXE");
        let elsewhere = format!(r"{VOLUME}\PROGRAMDATA\X\SVCHOST.EXE");
        assert_eq!(
            of_prefetch("SVCHOST.EXE", &table(&[&system32, &elsewhere]), SYSTEM_ROOT),
            None
        );
        // The same answer twice is still that answer.
        assert_eq!(
            of_prefetch("SVCHOST.EXE", &table(&[&system32, &system32]), SYSTEM_ROOT),
            Some(false)
        );
    }
}
