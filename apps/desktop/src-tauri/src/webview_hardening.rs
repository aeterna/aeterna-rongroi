// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `WebView2` settings that keep the window from writing next to the executable or calling Microsoft
//! `SmartScreen`. What cannot be controlled from here is documented in ADR 0001 and `PRIVACY.md`.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rongroi_host::Host;
use tauri::{App, WebviewUrl, WebviewWindowBuilder};

/// Extra `WebView2` browser arguments. `None` keeps wry's default, which already disables
/// `msSmartScreenProtection`. Setting a value replaces that default, so any value must re-include it.
const EXTRA_BROWSER_ARGS: Option<&str> = None;

/// Feature that must stay disabled whatever browser arguments are used.
#[cfg(test)]
const SMARTSCREEN_FEATURE: &str = "msSmartScreenProtection";

/// The start of every per-run profile folder's name. The rest of the name is the process id.
const DATA_DIR_PREFIX: &str = "aeterna-rongroi-";

/// Per-run `WebView2` profile folder under the system temp directory.
pub fn run_data_dir() -> PathBuf {
    data_dir_in(&std::env::temp_dir(), std::process::id())
}

fn data_dir_in(temp: &Path, pid: u32) -> PathBuf {
    temp.join(format!("{DATA_DIR_PREFIX}{pid}"))
}

/// Creates the only window, with the hardened `WebView2` settings.
pub fn build_main_window(app: &App, data_dir: &Path) -> tauri::Result<()> {
    let mut builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
        .title("aeterna-rongroi")
        .inner_size(960.0, 760.0)
        .data_directory(data_dir.to_path_buf())
        .incognito(true);
    if let Some(args) = EXTRA_BROWSER_ARGS {
        builder = builder.additional_browser_args(args);
    }
    builder.build()?;
    Ok(())
}

/// Deletes the per-run profile folder. `WebView2` processes can hold files briefly after exit, so retry.
pub fn remove_data_dir(data_dir: &Path) {
    for _ in 0..20 {
        if !data_dir.exists() || std::fs::remove_dir_all(data_dir).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Deletes the profile folders earlier runs of this program left in the temp directory because they
/// were stopped before their `RunEvent::Exit` handler ran — killed from Task Manager, for example.
///
/// Called after the scan, so it cannot change what was measured. Only a folder whose name
/// [`run_data_dir`] could have written, and whose process is not running, is removed: a folder is
/// kept when it belongs to this process, when a running process has its id (another copy of this
/// program, or a process that reused the id), and whenever the process list cannot be read.
pub fn remove_stale_data_dirs(host: &dyn Host) {
    remove_stale_data_dirs_in(&std::env::temp_dir(), std::process::id(), host);
}

fn remove_stale_data_dirs_in(temp: &Path, own_pid: u32, host: &dyn Host) {
    // Listed before the process list is read: a folder listed here was created by a process that
    // had started by then, so if that process is still running it is in the list read next.
    let candidates = data_dirs_in(temp);
    if candidates.is_empty() {
        return;
    }
    let Ok(processes) = host.running_processes() else {
        return;
    };
    let running: HashSet<u32> = processes.iter().map(|process| process.pid).collect();
    for (pid, dir) in candidates {
        if pid != own_pid && !running.contains(&pid) {
            // Best effort: a folder that cannot be removed now is tried again at the next start.
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// The folders directly in `temp` named exactly as [`run_data_dir`] names one, with the process id
/// each name carries. Links are not followed and files are skipped.
fn data_dirs_in(temp: &Path) -> Vec<(u32, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(temp) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| Some((owner_pid(&entry.file_name())?, entry.path())))
        .collect()
}

/// The process id in a profile folder's name, when the name is exactly `aeterna-rongroi-<id>` as
/// [`run_data_dir`] writes it: decimal digits, no sign and no leading zero.
fn owner_pid(name: &OsStr) -> Option<u32> {
    let digits = name.to_str()?.strip_prefix(DATA_DIR_PREFIX)?;
    let pid: u32 = digits.parse().ok()?;
    (pid.to_string() == digits).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_browser_args_must_keep_smartscreen_disabled() {
        assert!(EXTRA_BROWSER_ARGS.is_none_or(|args| args.contains(SMARTSCREEN_FEATURE)));
    }

    #[test]
    fn profile_folder_is_in_temp_and_unique_to_this_run() {
        let dir = run_data_dir();
        assert!(dir.starts_with(std::env::temp_dir()));
        assert!(
            dir.to_string_lossy()
                .ends_with(&std::process::id().to_string())
        );
    }

    #[test]
    fn removing_a_missing_folder_is_a_no_op() {
        remove_data_dir(&std::env::temp_dir().join("aeterna-rongroi-does-not-exist"));
    }

    #[test]
    fn only_a_name_this_program_writes_carries_a_process_id() {
        assert_eq!(owner_pid(OsStr::new("aeterna-rongroi-4242")), Some(4242));
        assert_eq!(owner_pid(OsStr::new("aeterna-rongroi-0")), Some(0));
        for name in [
            "aeterna-rongroi-",
            "aeterna-rongroi-04242",
            "aeterna-rongroi-+4242",
            "aeterna-rongroi--1",
            "aeterna-rongroi-4242x",
            "aeterna-rongroi-4242.old",
            "aeterna-rongroi-99999999999",
            "aeterna-rongroi-fork-4242",
            "Aeterna-Rongroi-4242",
            "other-4242",
            "4242",
        ] {
            assert_eq!(owner_pid(OsStr::new(name)), None, "{name}");
        }
    }

    /// A folder of its own under the system temp directory, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rongroi-desktop-test-{label}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn folder(&self, name: &str) -> PathBuf {
            let dir = self.0.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("Local State"), b"{}").unwrap();
            dir
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn host_running(pids: &[u32]) -> rongroi_host::FixtureHost {
        let listed: Vec<String> = pids
            .iter()
            .map(|pid| format!("{{ pid: {pid}, name: running.exe }}"))
            .collect();
        let yaml = format!("platform: windows\nprocesses: [{}]\n", listed.join(", "));
        rongroi_host::FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
    }

    #[test]
    fn a_folder_left_by_a_process_that_is_gone_is_removed() {
        let scratch = Scratch::new("stale");
        let gone = scratch.folder("aeterna-rongroi-111");
        let running = scratch.folder("aeterna-rongroi-222");
        let own = scratch.folder("aeterna-rongroi-333");
        remove_stale_data_dirs_in(&scratch.0, 333, &host_running(&[222]));
        assert!(!gone.exists());
        assert!(running.exists(), "a running process's folder was removed");
        assert!(own.exists(), "this process's own folder was removed");
    }

    #[test]
    fn nothing_but_this_programs_folders_is_touched() {
        let scratch = Scratch::new("others");
        let kept = [
            scratch.folder("aeterna-rongroi-0111"),
            scratch.folder("aeterna-rongroi-111.old"),
            scratch.folder("aeterna-rongroi-fork-111"),
            scratch.folder("other-111"),
        ];
        let file = scratch.0.join("aeterna-rongroi-444");
        std::fs::write(&file, b"not a folder").unwrap();
        remove_stale_data_dirs_in(&scratch.0, 999, &host_running(&[]));
        for dir in &kept {
            assert!(dir.exists(), "{}", dir.display());
        }
        assert!(
            file.exists(),
            "a file with a profile folder's name was removed"
        );
    }

    /// Without the process list there is no telling a folder in use from one left behind.
    #[test]
    fn every_folder_is_kept_when_the_process_list_cannot_be_read() {
        let scratch = Scratch::new("unreadable");
        let dir = scratch.folder("aeterna-rongroi-111");
        let host =
            rongroi_host::FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        remove_stale_data_dirs_in(&scratch.0, 999, &host);
        assert!(dir.exists());
        remove_stale_data_dirs_in(&scratch.0, 999, &rongroi_host::NonWindowsHost);
        assert!(dir.exists());
    }

    /// A link with a profile folder's name is not followed, so what it points to survives.
    #[cfg(unix)]
    #[test]
    fn a_link_with_a_profile_folders_name_is_not_followed() {
        let scratch = Scratch::new("link");
        let target = scratch.folder("target");
        std::os::unix::fs::symlink(&target, scratch.0.join("aeterna-rongroi-111")).unwrap();
        remove_stale_data_dirs_in(&scratch.0, 999, &host_running(&[]));
        assert!(target.join("Local State").exists());
    }
}
