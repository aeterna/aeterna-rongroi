// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The one list of names for loaded files (ADR 0082, sections 1 and 3). The `prefetch` collector
//! and the game-window view both read these names, so they share this module rather than keeping
//! two copies that could drift apart.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_loaded_files_accepts_timeline_names_and_loader_hosts_in_any_case() {
        for name in [
            "FiveM.exe",
            "GTA5_Enhanced.exe",
            "PlayGTAV.exe",
            "FiveM_b3258_GTAProcess.exe",
            "RUNDLL32.EXE",
            "regsvr32.exe",
        ] {
            assert!(counts_loaded_files(name), "{name} should count as a loaded file");
        }
    }

    #[test]
    fn counts_loaded_files_rejects_other_names() {
        for name in ["cmd.exe", "rundll32.dll", "fivem.exe.bak", ""] {
            assert!(!counts_loaded_files(name), "{name:?} should not count as a loaded file");
        }
    }

    #[test]
    fn has_pe_extension_reads_the_extension_of_the_last_path_segment() {
        for name in [
            "x.DLL",
            r"C:\a\b.mui",
            r"\VOLUME{01-02}\USERS\U\X.SYS",
            "a.b.exe",
        ] {
            assert!(has_pe_extension(name), "{name} should have a PE extension");
        }
    }

    #[test]
    fn has_pe_extension_rejects_names_without_a_pe_extension() {
        for name in ["x.png", "x", "x.dll.png", r"folder.dll\file", "a."] {
            assert!(!has_pe_extension(name), "{name:?} should not have a PE extension");
        }
    }

    #[test]
    fn pe_extensions_keeps_its_ten_values_in_order() {
        assert_eq!(
            PE_EXTENSIONS,
            ["exe", "dll", "sys", "scr", "com", "cpl", "ocx", "drv", "efi", "mui"]
        );
    }

    #[test]
    fn is_timeline_name_keeps_its_behaviour() {
        assert!(is_timeline_name("GTA5.exe"));
        assert!(is_timeline_name("fivem_b2802_gtaprocess.exe"));
        assert!(!is_timeline_name("fivem-cef-subprocess.exe"));
        assert!(!is_timeline_name("rundll32.exe"));
    }
}
