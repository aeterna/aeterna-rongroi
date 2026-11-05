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

/// Everything the UI may ask for. Created before any window exists; the report is never changed afterwards.
pub struct AppState {
    bundle: Bundle,
    report: Report,
    /// When the scan returned, for a saved record (ADR 0073).
    scan_finished_at: String,
    /// The saved record's bytes, once the player confirmed SS mode: serialised once, and what both the
    /// digest on screen and the file are taken from (ADR 0073).
    saved: std::sync::Mutex<Option<Vec<u8>>>,
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
- the words in PowerShell's commands, kept only as kinds — whether a command downloaded something and \
ran it, told Microsoft Defender to look away, cleared a log or history, or named FiveM — from the \
history of commands typed into a PowerShell window, the scripts Windows PowerShell flagged as \
suspicious, and the command lines it was started with. No command is kept or shown; the one thing \
kept is the name of a website a command downloaded from.\n\n\
- the files of programs Windows recorded running (BAM, Program Compatibility Assistant, the programs \
running now): what kind of content each holds, its hash, digital signature and version name, the \
download zone Windows wrote on it, and the name of the website it came from — never the rest of the \
address — starting nearest your last FiveM or GTA V session, for up to 90 seconds. It also reads the \
Windows drive's change journal, to find when any of those files was deleted or renamed. File names in \
the journal are compared on this PC and never kept. Reading a file can \
update its last-access time.\n\n\
Nothing is sent anywhere. In SS mode a server's name and a website's name are each shown only if \
you agree to that separately.\n\nYes: full scan. No: standard scan.\n\n\
การสแกนแบบ Full อ่านมากกว่าการสแกนแบบมาตรฐาน:\n\n\
- ชื่อโฟลเดอร์ cache ของแต่ละเซิร์ฟเวอร์ที่ FiveM for GTA V Enhanced เก็บไว้ หนึ่งโฟลเดอร์ต่อหนึ่งเซิร์ฟเวอร์ที่เครื่องนี้เคยเข้า \
พร้อมเวลาที่สร้างกับเวลาที่แก้ไขล่าสุด ยังไม่รู้ว่าชื่อนี้คำนวณมาจากอะไร แต่ชื่อของเซิร์ฟเวอร์เดิมบนเครื่องนี้จะเหมือนเดิม \
จึงจับคู่รายงานสองฉบับจากเครื่องนี้ได้\n\n\
- คำในคำสั่ง PowerShell โดยเก็บไว้แค่เป็นชนิด — คำสั่งนั้นดาวน์โหลดแล้วรันอะไรหรือไม่ สั่งให้ Microsoft Defender มองข้ามบางอย่างหรือไม่ \
ล้าง log หรือประวัติหรือไม่ หรือพูดถึง FiveM หรือไม่ — จากประวัติคำสั่งที่พิมพ์ในหน้าต่าง PowerShell, script ที่ Windows PowerShell \
ตั้งธงว่าน่าสงสัย และ command line ที่ใช้เปิดมัน ไม่เก็บและไม่แสดงคำสั่งใด ๆ สิ่งเดียวที่เก็บคือชื่อเว็บไซต์ที่คำสั่งดาวน์โหลดมา\n\n\
- ไฟล์ของโปรแกรมที่ Windows บันทึกว่าเคยรัน (BAM, Program Compatibility Assistant, โปรแกรมที่กำลังรัน): เนื้อไฟล์เป็นชนิดไหน hash ลายเซ็นดิจิทัล และชื่อในข้อมูลเวอร์ชัน โซนดาวน์โหลดที่ Windows เขียนไว้บนไฟล์ และชื่อเว็บไซต์ที่ไฟล์มาจาก โดยไม่เก็บส่วนอื่นของที่อยู่ เริ่มจากไฟล์ที่ใกล้เซสชัน FiveM หรือ GTA V ล่าสุดก่อน ใช้เวลาไม่เกิน 90 วินาที และอ่าน change journal ของไดรฟ์ Windows เพื่อดูว่าไฟล์เหล่านั้นเคยถูกลบหรือเปลี่ยนชื่อเมื่อไร ชื่อไฟล์ใน journal ถูกเทียบบนเครื่องนี้เท่านั้นและไม่ถูกเก็บไว้ การอ่านไฟล์อาจทำให้เวลาเข้าถึงล่าสุดของไฟล์เปลี่ยน\n\n\
ไม่ส่งอะไรออกไปไหน ในโหมด SS ชื่อเซิร์ฟเวอร์และชื่อเว็บไซต์จะแสดงก็ต่อเมื่อคุณยินยอมแยกทีละข้อ\n\n\
Yes: สแกนแบบ Full  No: สแกนแบบมาตรฐาน";

/// The splash shown while the scan runs, in both languages because no language has been chosen yet
/// (ADR 0092). It says a scan is running and names no duration for a standard scan, because none was
/// measured.
const SPLASH_TITLE: &str = "aeterna-rongroi";
const SPLASH_STANDARD_LINES: [&str; 2] = ["กำลังสแกนเครื่องนี้", "Scanning this PC"];
/// A full scan's two extra lines, in Thai and English. The 90 seconds is a ceiling for the part that
/// reads the files of recorded programs, not the length of the whole scan, so the line says so
/// (ADR 0092).
const SPLASH_FULL_LINES: [&str; 2] = [
    "สแกนแบบ Full: ส่วนไฟล์โปรแกรมไม่เกิน 90 วินาที",
    "Full scan: program files up to 90 seconds",
];

/// The splash's lines for `tier`, Thai and English together (ADR 0092).
fn splash_lines(tier: ScanTier) -> Vec<&'static str> {
    let mut lines = SPLASH_STANDARD_LINES.to_vec();
    if tier == ScanTier::Full {
        lines.extend(SPLASH_FULL_LINES);
    }
    lines
}

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
    // The splash is open before the scan reads anything and closes as soon as it returns; it also
    // closes on drop, so an early return or a panic during the scan leaves no window (ADR 0092).
    let splash = show_splash(tier);

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
    let scan_finished_at = jiff::Timestamp::now().to_string();
    close_splash(splash);

    // 2. Only now create the UI, with its profile in a per-run temporary folder. The folders earlier
    //    runs could not delete because they were stopped go first; the scan is already over.
    webview_hardening::remove_stale_data_dirs(host.as_ref());
    let data_dir = webview_hardening::run_data_dir();
    let window_dir = data_dir.clone();
    let app = tauri::Builder::default()
        .manage(AppState {
            bundle,
            report,
            scan_finished_at,
            saved: std::sync::Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            commands::report_header,
            commands::report_view,
            commands::rule_texts,
            commands::age_texts,
            commands::relaunch_elevated,
            commands::relaunch_full,
            commands::code_links,
            commands::code_link_qr,
            commands::build_saved_record,
            commands::save_saved_record
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

/// What keeps the scan's splash open: the window on Windows, nothing anywhere else.
#[cfg(windows)]
type SplashGuard = rongroi_host_windows::splash::Splash;

/// No Windows, no window to keep open.
#[cfg(not(windows))]
struct SplashGuard;

/// Opens the splash for `tier` before the scan reads anything (ADR 0092).
#[cfg(windows)]
fn show_splash(tier: ScanTier) -> SplashGuard {
    rongroi_host_windows::splash::Splash::show(SPLASH_TITLE, &splash_lines(tier))
}

/// No Windows, no splash, so a splash never stops a scan.
#[cfg(not(windows))]
fn show_splash(tier: ScanTier) -> SplashGuard {
    let _ = (splash_lines(tier), SPLASH_TITLE);
    SplashGuard
}

/// Closes the window once the scan has returned; the splash also closes on drop (ADR 0092).
#[cfg(windows)]
fn close_splash(splash: SplashGuard) {
    splash.close();
}

/// No Windows, nothing to close.
#[cfg(not(windows))]
fn close_splash(_splash: SplashGuard) {}

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

    /// ADR 0079 section 6: the full-scan text names the files the recorded programs point at, in
    /// both languages.
    #[test]
    fn the_full_scan_text_names_the_files_of_recorded_programs() {
        for words in [
            "programs Windows recorded running",
            "โปรแกรมที่ Windows บันทึกว่าเคยรัน",
        ] {
            assert!(FULL_TEXT.contains(words), "{words} missing from FULL_TEXT");
        }
    }

    /// ADR 0086 section 6: the full-scan dialog says what the CLI's full-scan list says about the change
    /// journal, word for word, in both languages.
    #[test]
    fn the_full_scan_text_names_the_change_journal_read_for_recorded_files() {
        for sentence in [
            "It also reads the Windows drive's change journal, to find when any of those files was deleted or renamed. File names in the journal are compared on this PC and never kept.",
            "และอ่าน change journal ของไดรฟ์ Windows เพื่อดูว่าไฟล์เหล่านั้นเคยถูกลบหรือเปลี่ยนชื่อเมื่อไร ชื่อไฟล์ใน journal ถูกเทียบบนเครื่องนี้เท่านั้นและไม่ถูกเก็บไว้",
        ] {
            assert!(
                FULL_TEXT.contains(sentence),
                "{sentence} missing from FULL_TEXT"
            );
        }
    }

    /// ADR 0092 section 3: a splash line has to fit the window — about 50 characters — and at most
    /// five lines fit above the strip.
    #[test]
    fn the_splash_lines_fit_the_window() {
        for tier in [ScanTier::Standard, ScanTier::Full] {
            let lines = splash_lines(tier);
            let count = lines.len();
            assert!(count <= 5, "{tier:?} has {count} lines");
            for line in lines {
                let length = line.chars().count();
                assert!(length <= 50, "{line} is {length} characters");
            }
        }
    }

    /// ADR 0092 section 3: a standard scan states no duration, because none was measured; a full scan
    /// states the same 90 seconds the full-scan dialog states, and only that number.
    #[test]
    fn the_full_splash_ties_its_90_seconds_to_the_dialog() {
        for line in splash_lines(ScanTier::Standard) {
            assert!(
                !line.chars().any(|character| character.is_ascii_digit()),
                "{line} has a digit"
            );
        }
        let full = splash_lines(ScanTier::Full);
        assert!(full.iter().any(|line| line.contains("90")));
        assert!(FULL_TEXT.contains("90"));
    }

    /// ADR 0092 section 3: the standard splash says only that a scan is running, in both languages.
    #[test]
    fn the_standard_splash_says_only_that_a_scan_is_running() {
        assert_eq!(
            splash_lines(ScanTier::Standard),
            vec!["กำลังสแกนเครื่องนี้", "Scanning this PC"]
        );
    }

    /// ADR 0092 section 3: a full scan adds exactly two lines to the standard scan's: the Thai and
    /// the English line about program files.
    #[test]
    fn the_full_splash_is_the_standard_one_with_two_more_lines() {
        let standard = splash_lines(ScanTier::Standard);
        let full = splash_lines(ScanTier::Full);
        assert_eq!(full.len(), standard.len() + 2);
        assert_eq!(&full[..standard.len()], &standard[..]);
        assert_eq!(
            &full[standard.len()..],
            &[
                "สแกนแบบ Full: ส่วนไฟล์โปรแกรมไม่เกิน 90 วินาที",
                "Full scan: program files up to 90 seconds",
            ]
        );
    }

    /// ADR 0092 section 3: no language has been chosen yet, so the splash carries Thai and English.
    #[test]
    fn the_splash_lines_carry_both_languages() {
        for tier in [ScanTier::Standard, ScanTier::Full] {
            let lines = splash_lines(tier);
            let has_thai = lines.iter().any(|line| {
                line.chars()
                    .any(|character| ('\u{0E00}'..='\u{0E7F}').contains(&character))
            });
            assert!(has_thai, "{tier:?} has no Thai line");
            let has_ascii = lines.iter().copied().any(str::is_ascii);
            assert!(has_ascii, "{tier:?} has no ASCII line");
        }
    }
}
