// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! IPC commands. They only read the frozen report; filtering and redaction happen in `rongroi_core::view`.

// Tauri injects `State` by value; commands cannot take it by reference.
#![allow(clippy::needless_pass_by_value)]

use std::collections::BTreeMap;

use rongroi_core::model::{Mode, ReportHeader};
use rongroi_core::provenance::REPOSITORY_URL;
use rongroi_core::rules::RuleText;
use rongroi_core::view::{self, ReportView};
use tauri::State;

use crate::AppState;

/// Facts about the scan without evidence, for the start screen and the unofficial-build banner. The
/// header as the core shows it outside a view, whatever the mode (ADR 0049).
#[tauri::command]
pub fn report_header(state: State<'_, AppState>) -> ReportHeader {
    view::shown_header(&state.report)
}

/// The report as `mode` may see it.
#[tauri::command]
pub fn report_view(state: State<'_, AppState>, mode: Mode) -> ReportView {
    view::for_mode(&state.report, mode)
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
pub fn relaunch_elevated(app: tauri::AppHandle) -> ElevateOutcome {
    relaunch(&app)
}

#[cfg(windows)]
fn relaunch(app: &tauri::AppHandle) -> ElevateOutcome {
    use rongroi_host_windows::elevate::{self, ElevateError};

    let args: Vec<String> = std::env::args().skip(1).collect();
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
fn relaunch(_app: &tauri::AppHandle) -> ElevateOutcome {
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
