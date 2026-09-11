// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `WebView2` settings that keep the window from writing next to the executable or calling Microsoft
//! `SmartScreen`. What cannot be controlled from here is documented in ADR 0001 and `PRIVACY.md`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tauri::{App, WebviewUrl, WebviewWindowBuilder};

/// Extra `WebView2` browser arguments. `None` keeps wry's default, which already disables
/// `msSmartScreenProtection`. Setting a value replaces that default, so any value must re-include it.
const EXTRA_BROWSER_ARGS: Option<&str> = None;

/// Feature that must stay disabled whatever browser arguments are used.
#[cfg(test)]
const SMARTSCREEN_FEATURE: &str = "msSmartScreenProtection";

/// Per-run `WebView2` profile folder under the system temp directory.
pub fn run_data_dir() -> PathBuf {
    std::env::temp_dir().join(format!("aeterna-rongroi-{}", std::process::id()))
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
}
