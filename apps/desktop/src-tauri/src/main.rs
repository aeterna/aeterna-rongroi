// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! aeterna-rongroi desktop app. Scans first, freezes the report, then opens a hardened window (ADR 0001).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod webview_hardening;

use rongroi_collectors::scan::{self, ScanContext};
use rongroi_core::bundle::Bundle;
use rongroi_core::model::Report;
use rongroi_core::provenance::Provenance;
use rongroi_host::Host;

/// Everything the UI may ask for. Created before any window exists and never changed afterwards.
pub struct AppState {
    bundle: Bundle,
    report: Report,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Scan before the WebView exists, so nothing the window does can change what was measured.
    let bundle = Bundle::embedded()?;
    let context = ScanContext {
        provenance: Provenance::current(),
        generated_at: jiff::Timestamp::now().to_string(),
    };
    let host = live_host();
    let report = scan::run(host.as_ref(), &bundle, context);

    // 2. Only now create the UI, with its profile in a per-run temporary folder.
    let data_dir = webview_hardening::run_data_dir();
    let window_dir = data_dir.clone();
    let app = tauri::Builder::default()
        .manage(AppState { bundle, report })
        .invoke_handler(tauri::generate_handler![
            commands::report_header,
            commands::report_view,
            commands::rule_texts
        ])
        .setup(move |app| {
            webview_hardening::build_main_window(app, &window_dir)?;
            Ok(())
        })
        .build(tauri::generate_context!())?;

    app.run(move |_handle, event| {
        if let tauri::RunEvent::Exit = event {
            webview_hardening::remove_data_dir(&data_dir);
        }
    });
    Ok(())
}

#[cfg(windows)]
fn live_host() -> Box<dyn Host> {
    Box::new(rongroi_host_windows::LiveHost)
}

#[cfg(not(windows))]
fn live_host() -> Box<dyn Host> {
    Box::new(rongroi_host::NonWindowsHost)
}
