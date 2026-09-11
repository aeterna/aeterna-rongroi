// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! IPC commands. They only read the frozen report; filtering and redaction happen in `rongroi_core::view`.

// Tauri injects `State` by value; commands cannot take it by reference.
#![allow(clippy::needless_pass_by_value)]

use std::collections::BTreeMap;

use rongroi_core::model::{Mode, ReportHeader};
use rongroi_core::rules::RuleText;
use rongroi_core::view::{self, ReportView};
use tauri::State;

use crate::AppState;

/// Facts about the scan without evidence, for the start screen and the unofficial-build banner.
#[tauri::command]
pub fn report_header(state: State<'_, AppState>) -> ReportHeader {
    state.report.header.clone()
}

/// The report as `mode` may see it.
#[tauri::command]
pub fn report_view(state: State<'_, AppState>, mode: Mode) -> ReportView {
    view::for_mode(&state.report, mode)
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
