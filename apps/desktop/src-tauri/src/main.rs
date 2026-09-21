// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! aeterna-rongroi desktop app. Scans first, freezes the report, then opens a hardened window (ADR 0001).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod qr;
mod webview_hardening;

use rongroi_collectors::scan::{self, ScanContext};
use rongroi_core::bundle::Bundle;
use rongroi_core::engine::SelfIdentity;
use rongroi_core::model::{Report, ScanTier};
use rongroi_core::provenance::Provenance;
use rongroi_host::Host;

/// Everything the UI may ask for. Created before any window exists and never changed afterwards.
pub struct AppState {
    bundle: Bundle,
    report: Report,
}

/// The flag that asks for a full scan (ADR 0052). It only asks: [`chosen_tier`] decides.
pub const FULL_FLAG: &str = "--full";

/// The question a copy started with `--full` asks, in both languages because no language has been
/// chosen yet, before any collector runs and before any `WebView` exists (ADR 0052).
const FULL_TITLE: &str = "aeterna-rongroi — full scan / สแกนแบบ Full";
const FULL_TEXT: &str = "A full scan reads more than the standard scan:\n\n\
- the name of each server cache folder FiveM for GTA V Enhanced keeps — one per server this PC \
joined — with when it was created and last changed. What the name is made from is not known; it \
stays the same for that server on this PC, so it can match two reports of this PC.\n\n\
Nothing is read differently and nothing is sent anywhere. In SS mode a server's name is shown only \
if you agree to that separately.\n\nYes: full scan. No: standard scan.\n\n\
การสแกนแบบ Full อ่านมากกว่าการสแกนแบบมาตรฐาน:\n\n\
- ชื่อโฟลเดอร์ cache ของแต่ละเซิร์ฟเวอร์ที่ FiveM for GTA V Enhanced เก็บไว้ หนึ่งโฟลเดอร์ต่อหนึ่งเซิร์ฟเวอร์ที่เครื่องนี้เคยเข้า \
พร้อมเวลาที่สร้างกับเวลาที่แก้ไขล่าสุด ยังไม่รู้ว่าชื่อนี้คำนวณมาจากอะไร แต่ชื่อของเซิร์ฟเวอร์เดิมบนเครื่องนี้จะเหมือนเดิม \
จึงจับคู่รายงานสองฉบับจากเครื่องนี้ได้\n\n\
ไม่ได้อ่านสิ่งใดต่างไปจากเดิม และไม่ส่งอะไรออกไปไหน ในโหมด SS ชื่อเซิร์ฟเวอร์จะแสดงก็ต่อเมื่อคุณยินยอมแยกอีกข้อหนึ่ง\n\n\
Yes: สแกนแบบ Full  No: สแกนแบบมาตรฐาน";

/// The scan this copy runs: full only when it was started with `--full` **and** the person answered
/// Yes in the dialog it shows now. The flag alone never reads anything (ADR 0052).
fn chosen_tier(args: &[String], ask: impl FnOnce() -> bool) -> ScanTier {
    if args.iter().any(|arg| arg == FULL_FLAG) && ask() {
        ScanTier::Full
    } else {
        ScanTier::Standard
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 0. Which scan, asked in a window Windows draws, before anything is read (ADR 0052).
    let args: Vec<String> = std::env::args().skip(1).collect();
    let tier = chosen_tier(&args, ask_full);

    // 1. Scan before the WebView exists, so nothing the window does can change what was measured.
    let bundle = Bundle::embedded()?;
    let provenance = Provenance::current();
    // This program is in its own process list while it scans. The engine needs to know what "this
    // program" is to separate those traces from evidence about the PC (ADR 0010); the executable's
    // digest is the one the header already carries, so it is not read twice.
    let self_identity = SelfIdentity {
        exe_path: std::env::current_exe()
            .ok()
            .map(|path| path.display().to_string()),
        exe_sha256: provenance.exe_sha256.clone(),
    };
    let context = ScanContext {
        provenance,
        generated_at: jiff::Timestamp::now().to_string(),
        self_identity,
        tier,
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
            commands::rule_texts,
            commands::relaunch_elevated,
            commands::relaunch_full,
            commands::code_links,
            commands::code_link_qr
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
fn ask_full() -> bool {
    rongroi_host_windows::dialog::ask_yes_no(FULL_TITLE, FULL_TEXT)
}

/// No Windows, no dialog, and so no agreement to a full scan.
#[cfg(not(windows))]
fn ask_full() -> bool {
    let _ = (FULL_TITLE, FULL_TEXT);
    false
}

#[cfg(windows)]
fn live_host() -> Box<dyn Host> {
    Box::new(rongroi_host_windows::LiveHost)
}

#[cfg(not(windows))]
fn live_host() -> Box<dyn Host> {
    Box::new(rongroi_host::NonWindowsHost)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn only_the_flag_and_a_yes_together_start_a_full_scan() {
        assert_eq!(chosen_tier(&args(&["--full"]), || true), ScanTier::Full);
        assert_eq!(
            chosen_tier(&args(&["--full"]), || false),
            ScanTier::Standard
        );
        // Without the flag the question is never asked.
        assert_eq!(
            chosen_tier(&args(&[]), || panic!("asked without --full")),
            ScanTier::Standard
        );
    }
}
