// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! IPC commands. They only read the frozen report; filtering and redaction happen in `rongroi_core::view`.

// Tauri injects `State` by value; commands cannot take it by reference.
#![allow(clippy::needless_pass_by_value)]

use std::collections::BTreeMap;

use rongroi_core::model::{Mode, ReportHeader, ScanTier};
use rongroi_core::provenance::REPOSITORY_URL;
use rongroi_core::rules::RuleText;
use rongroi_core::view::{self, ReportView, SsOptions};
use tauri::State;

use crate::AppState;

/// Facts about the scan without evidence, for the start screen and the unofficial-build banner. The
/// header as the core shows it outside a view, whatever the mode (ADR 0049).
#[tauri::command]
pub fn report_header(state: State<'_, AppState>) -> ReportHeader {
    view::shown_header(&state.report)
}

/// The report as `mode` may see it, with what the player agreed SS mode may show beyond its default
/// (ADR 0052). Leaving `options` out shows nothing more.
#[tauri::command]
pub fn report_view(
    state: State<'_, AppState>,
    mode: Mode,
    options: Option<SsOptions>,
) -> ReportView {
    view::for_mode_with(&state.report, mode, options.unwrap_or_default())
}

/// The arguments a new copy is started with: this copy's own, with `--full` only when `full` is true.
///
/// A copy whose player answered No to the full-scan question still carries the flag; forwarding it
/// to an elevated copy would ask again for a scan the player just declined (ADR 0052).
fn forwarded_args(args: impl IntoIterator<Item = String>, full: bool) -> Vec<String> {
    let mut forwarded: Vec<String> = args
        .into_iter()
        .filter(|arg| arg != crate::FULL_FLAG)
        .collect();
    if full {
        forwarded.push(crate::FULL_FLAG.to_owned());
    }
    forwarded
}

/// Starts a copy of this program with `--full` and the same token, and closes this one (ADR 0052).
///
/// The new copy asks the full-scan question in a native dialog before it reads anything; nothing is
/// handed over, as for [`relaunch_elevated`]. `Started` or `Failed`: there is no prompt to decline here.
#[tauri::command]
pub fn relaunch_full(app: tauri::AppHandle) -> ElevateOutcome {
    relaunch_for_full(&app)
}

#[cfg(windows)]
fn relaunch_for_full(app: &tauri::AppHandle) -> ElevateOutcome {
    let args = forwarded_args(std::env::args().skip(1), true);
    match rongroi_host_windows::relaunch::relaunch_same_token(&args) {
        Ok(()) => {
            app.exit(0);
            ElevateOutcome::Started
        }
        Err(error) => {
            // Local stderr only (CONVENTIONS.md, section 4).
            eprintln!("relaunch for a full scan failed: {error}");
            ElevateOutcome::Failed
        }
    }
}

#[cfg(not(windows))]
fn relaunch_for_full(_app: &tauri::AppHandle) -> ElevateOutcome {
    ElevateOutcome::Failed
}

/// What came of a request to restart with administrator rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElevateOutcome {
    /// An elevated copy is starting and this one is closing.
    Started,
    /// The person dismissed the Windows prompt. A normal outcome, not a failure (ADR 0012).
    Declined,
    /// Windows did not start the elevated program.
    Failed,
}

/// Starts an elevated copy of this program and closes this one.
///
/// Nothing is handed over: the new process scans from the beginning on its own startup path, because a
/// report this process did not measure is not one it can show (ADR 0012).
#[tauri::command]
pub fn relaunch_elevated(state: State<'_, AppState>, app: tauri::AppHandle) -> ElevateOutcome {
    relaunch(&app, state.report.header.scan_tier == ScanTier::Full)
}

#[cfg(windows)]
fn relaunch(app: &tauri::AppHandle, full: bool) -> ElevateOutcome {
    use rongroi_host_windows::elevate::{self, ElevateError};

    // `--full` only when this scan was full, and the elevated copy asks again (ADR 0052).
    let args = forwarded_args(std::env::args().skip(1), full);
    match elevate::relaunch_elevated(&args) {
        Ok(()) => {
            // Exit through the handle, so the `RunEvent::Exit` handler still deletes this run's
            // WebView2 profile folder.
            app.exit(0);
            ElevateOutcome::Started
        }
        Err(ElevateError::Declined) => ElevateOutcome::Declined,
        Err(error) => {
            // Local stderr only (CONVENTIONS.md, section 4). A declined prompt never reaches here.
            eprintln!("relaunch with administrator rights failed: {error}");
            ElevateOutcome::Failed
        }
    }
}

#[cfg(not(windows))]
fn relaunch(_app: &tauri::AppHandle, _full: bool) -> ElevateOutcome {
    ElevateOutcome::Failed
}

/// Rule text in `lang`, keyed by rule id.
#[tauri::command]
pub fn rule_texts(state: State<'_, AppState>, lang: &str) -> BTreeMap<String, RuleText> {
    state
        .bundle
        .rules()
        .iter()
        .filter_map(|sourced| {
            let id = &sourced.rule.id;
            state.bundle.text(id, lang).map(|text| (id.clone(), text))
        })
        .collect()
}

/// Where this binary's code can be read (ADR 0045).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CodeLinks {
    /// The repository.
    pub repository: String,
    /// The commit of an official build, the repository otherwise.
    pub code: String,
    /// The commit whose code this binary is; `None` unless this is an official build.
    pub commit: Option<String>,
}

/// Where this binary's code can be read.
#[tauri::command]
pub fn code_links(state: State<'_, AppState>) -> CodeLinks {
    let provenance = &state.report.header.provenance;
    CodeLinks {
        repository: REPOSITORY_URL.to_owned(),
        code: provenance.code_url(),
        commit: provenance.code_commit().map(str::to_owned),
    }
}

/// A QR code of a link into the repository, as SVG text (ADR 0045).
#[tauri::command]
pub fn code_link_qr(url: &str) -> Option<String> {
    crate::qr::svg(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn full_is_forwarded_only_when_the_scan_was_full() {
        assert_eq!(forwarded_args(args(&["--full"]), false), args(&[]));
        assert_eq!(forwarded_args(args(&[]), true), args(&["--full"]));
        assert_eq!(
            forwarded_args(args(&["--full", "--full"]), true),
            args(&["--full"])
        );
    }
}
