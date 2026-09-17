// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Text output of the CLI in English and Thai.

use std::fmt::Write as _;

use clap::ValueEnum;
use rongroi_core::bundle::Bundle;
use rongroi_core::model::{BootTime, EvidenceState, Mode, Observation, UnmeasuredReason};
use rongroi_core::view::ReportView;

/// Output language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Lang {
    /// English.
    En,
    /// Thai.
    Th,
}

impl Lang {
    fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Th => "th",
        }
    }
}

const UNOFFICIAL: &str = "UNOFFICIAL BUILD";

fn text(lang: Lang, key: &str) -> &'static str {
    match (lang, key) {
        (Lang::En, "unofficial") => {
            "not built by the aeterna-rongroi release workflow. Do not rely on this result."
        }
        (Lang::Th, "unofficial") => "ไม่ได้สร้างจากระบบ release ของ aeterna-rongroi อย่าเชื่อผลตรวจนี้",
        (Lang::En, "official") => "official build",
        (Lang::Th, "official") => "build ทางการ",
        (Lang::En, "found") => "FOUND",
        (Lang::Th, "found") => "เจอ",
        (Lang::En, "not_found") => "NOT FOUND",
        (Lang::Th, "not_found") => "ไม่เจอ",
        (Lang::En, "hidden") => "Hidden in SS mode",
        (Lang::Th, "hidden") => "ซ่อนในโหมด SS",
        (Lang::En, "unmeasured_expected") => "NOT MEASURED (expected here)",
        (Lang::Th, "unmeasured_expected") => "ยังไม่ได้วัด (เป็นเรื่องปกติของเครื่องนี้)",
        (Lang::En, "unmeasured_unexpected") => "NOT MEASURED (not expected)",
        (Lang::Th, "unmeasured_unexpected") => "ยังไม่ได้วัด (ไม่ได้คาดไว้)",
        // The rule's own description, beside every state: it says what the check means and what it
        // does not prove, which is the sentence that stops a single row being read as a verdict.
        (Lang::En, "description") => "About this check",
        (Lang::Th, "description") => "เกี่ยวกับการตรวจนี้",
        // NIST SP 800-86 section 3.4's alternative explanations, beside a `found` row only.
        (Lang::En, "falsepositives") => "Ordinary things that also produce this",
        (Lang::Th, "falsepositives") => "เรื่องปกติที่ทำให้เกิดผลแบบนี้ได้เหมือนกัน",
        (Lang::En, "scope_not_admin") => {
            "Scope: {n} check(s) could not be answered because this scan does not have administrator \
             rights. Running it again as administrator answers them."
        }
        (Lang::Th, "scope_not_admin") => {
            "ขอบเขตการตรวจ: มี {n} รายการที่ตอบไม่ได้เพราะการสแกนครั้งนี้ไม่มีสิทธิ์ผู้ดูแลระบบ \
             เปิดใหม่ด้วยสิทธิ์ผู้ดูแลระบบแล้วจะตอบได้"
        }
        // The same shape as the line above and for the same reason: one fact about how far the scan
        // got, said once, rather than a row per rule it stopped (ADR 0030).
        (Lang::En, "scope_not_attempted") => {
            "Scope: {n} check(s) could not be answered because this program stopped reading before \
             it reached what they ask about. That is this program's limit, not a finding about \
             this PC."
        }
        (Lang::Th, "scope_not_attempted") => {
            "ขอบเขตการตรวจ: มี {n} รายการที่ตอบไม่ได้เพราะโปรแกรมหยุดอ่านก่อนจะถึงส่วนที่รายการนั้นถาม \
             เป็นข้อจำกัดของโปรแกรมนี้เอง ไม่ใช่สิ่งที่ตรวจเจอในเครื่องนี้"
        }
        // Context for reading every time below it, never a finding: the sentence after the time is
        // what stops "started three days ago" being read as something the player did (ADR 0039).
        (Lang::En, "boot_time") => {
            "Windows start: {at}, {since} before this scan. Not reset by \"Shut down\" with Fast \
             Startup (the Windows default), sleep or hibernation; reset by a restart."
        }
        (Lang::Th, "boot_time") => {
            "Windows เริ่มทำงาน: {at} ({since} ก่อนการสแกนนี้) การกด \"Shut down\" ขณะเปิด Fast Startup \
             (ค่าเริ่มต้นของ Windows) การ sleep และการ hibernate ไม่ทำให้ค่านี้เริ่มใหม่ การ restart ทำให้เริ่มใหม่"
        }
        (Lang::En, "boot_time_unmeasured") => "Windows start: not measured — {reason}",
        (Lang::Th, "boot_time_unmeasured") => "Windows เริ่มทำงาน: ยังไม่ได้วัด — {reason}",
        (Lang::En, "own_traces") => "own traces (excluded)",
        (Lang::Th, "own_traces") => "ร่องรอยของโปรแกรมนี้เอง (แยกออกแล้ว)",
        (Lang::En, "own_traces_note") => {
            "what this program itself left in what was read; not evidence about this PC"
        }
        (Lang::Th, "own_traces_note") => "สิ่งที่โปรแกรมนี้ทิ้งไว้เองในสิ่งที่อ่านมา ไม่ใช่หลักฐานเกี่ยวกับเครื่องนี้",
        (Lang::En, "unmatched") => "unmatched observations",
        (Lang::Th, "unmatched") => "สิ่งที่เห็นแต่ไม่ตรง rule ใดเลย",
        (Lang::En, "unmatched_note") => {
            "what the collectors saw that no rule matched; these are things that were seen, not findings"
        }
        (Lang::Th, "unmatched_note") => {
            "สิ่งที่ collector เห็นแต่ไม่มี rule ไหนตรงเลย เป็นสิ่งที่เห็น ไม่ใช่สิ่งที่ตรวจเจอ"
        }
        (Lang::En, "footer") => "Evidence only. This report cannot prove that a PC is clean.",
        (Lang::Th, "footer") => "เป็นหลักฐานประกอบเท่านั้น รายงานนี้พิสูจน์ไม่ได้ว่าเครื่องสะอาด",
        // Three counts of what this view lists, never one number (ADR 0045).
        (Lang::En, "listed") => {
            "Listed: {found} found · {not_found} not found · {unmeasured} not measured"
        }
        (Lang::Th, "listed") => {
            "รายการที่แสดง: เจอ {found} · ไม่เจอ {not_found} · ยังไม่ได้วัด {unmeasured}"
        }
        (Lang::En, "code") => "Code: {url}",
        (Lang::Th, "code") => "โค้ด: {url}",
        (Lang::En, "code_unknown") => {
            "Code: {url} (the code this build was made from is not known)"
        }
        (Lang::Th, "code_unknown") => "โค้ด: {url} (ไม่รู้ว่า build นี้สร้างจากโค้ดของ commit ไหน)",
        (Lang::En, "elevated_yes") => "administrator",
        (Lang::Th, "elevated_yes") => "สิทธิ์ผู้ดูแลระบบ",
        (Lang::En, "elevated_no") => "standard user",
        (Lang::Th, "elevated_no") => "ผู้ใช้ทั่วไป",
        (_, "elevated_unknown") => "?",
        _ => text_elevate(lang, key),
    }
}

/// Text for the elevation and consent flow, kept apart from [`text`] so that function stays under
/// clippy's line limit.
fn text_elevate(lang: Lang, key: &str) -> &'static str {
    match (lang, key) {
        (Lang::En, "declined") => "Scan cancelled. Nothing was read.",
        (Lang::Th, "declined") => "ยกเลิกการสแกนแล้ว ไม่ได้อ่านอะไรเลย",
        (Lang::En, "elevate_started") => {
            "Starting again with administrator rights. The new window does the scan."
        }
        (Lang::Th, "elevate_started") => "กำลังเปิดใหม่ด้วยสิทธิ์ผู้ดูแลระบบ หน้าต่างใหม่จะเป็นตัวสแกน",
        (Lang::En, "elevate_declined") => {
            "The administrator prompt was declined. Nothing was scanned."
        }
        (Lang::Th, "elevate_declined") => "ไม่ได้อนุญาตสิทธิ์ผู้ดูแลระบบ ยังไม่ได้สแกนอะไร",
        (Lang::En, "elevate_failed") => "could not start again with administrator rights",
        (Lang::Th, "elevate_failed") => "เปิดใหม่ด้วยสิทธิ์ผู้ดูแลระบบไม่สำเร็จ",
        (Lang::En, "elevate_not_windows") => {
            "Administrator rights are a Windows idea; --elevate does nothing on this system."
        }
        // The elevated copy runs in a console window of its own, which Windows closes the moment
        // the process exits (ADR 0012, amended).
        (Lang::En, "pause_at_exit") => "Press Enter to close this window.",
        (Lang::Th, "pause_at_exit") => "กด Enter เพื่อปิดหน้าต่างนี้",
        (Lang::Th, "elevate_not_windows") => "สิทธิ์ผู้ดูแลระบบเป็นเรื่องของ Windows --elevate ไม่มีผลบนระบบนี้",
        _ => "",
    }
}

/// The one line a non-expert reads beside an unmeasured result.
///
/// Two rules, both borrowed and both about not letting a state read as an accusation (ADR 0030):
/// name the thing that was not seen and never the person, and say it about the record or about this
/// program rather than about the machine's owner. The same twelve strings are in
/// `apps/desktop/src/locales/<lang>/report.json` under `reason.*`; the CLI does not load those files,
/// so the two are kept in step by `every_reason_has_a_word_in_both_languages` here and by
/// `check-locales` there.
fn reason(lang: Lang, reason: UnmeasuredReason) -> &'static str {
    match (lang, reason) {
        (Lang::En, UnmeasuredReason::NotWindows) => "not running on Windows",
        (Lang::Th, UnmeasuredReason::NotWindows) => "ไม่ได้รันบน Windows",
        (Lang::En, UnmeasuredReason::NotOnThisOs) => {
            "this version of Windows does not keep this record"
        }
        (Lang::Th, UnmeasuredReason::NotOnThisOs) => "Windows รุ่นนี้ไม่ได้เก็บข้อมูลส่วนนี้",
        (Lang::En, UnmeasuredReason::NotAdmin) => {
            "Windows would not show this without administrator rights"
        }
        (Lang::Th, UnmeasuredReason::NotAdmin) => "ต้องมีสิทธิ์ผู้ดูแลระบบ Windows จึงจะให้อ่าน",
        (Lang::En, UnmeasuredReason::NotAttempted) => {
            "this was not read — the scan stopped before reaching it"
        }
        (Lang::Th, UnmeasuredReason::NotAttempted) => "ไม่ได้อ่านส่วนนี้ เพราะการสแกนหยุดก่อนจะถึง",
        (Lang::En, UnmeasuredReason::AccessDenied) => "Windows refused to open this",
        (Lang::Th, UnmeasuredReason::AccessDenied) => "Windows ไม่อนุญาตให้เปิดอ่าน",
        (Lang::En, UnmeasuredReason::ServiceDisabled) => {
            "the Windows service that writes this record is switched off"
        }
        (Lang::Th, UnmeasuredReason::ServiceDisabled) => "บริการของ Windows ที่เขียนข้อมูลนี้ถูกปิดอยู่",
        (Lang::En, UnmeasuredReason::SourceAbsent) => "this PC has no such record to read",
        (Lang::Th, UnmeasuredReason::SourceAbsent) => "เครื่องนี้ไม่มีข้อมูลส่วนนี้ให้อ่าน",
        (Lang::En, UnmeasuredReason::SourceEmpty) => {
            "the place this is kept is there and holds nothing"
        }
        (Lang::Th, UnmeasuredReason::SourceEmpty) => "มีที่เก็บข้อมูลอยู่ แต่ว่างเปล่า",
        (Lang::En, UnmeasuredReason::Partial) => "part of this was read and part of it was not",
        (Lang::Th, UnmeasuredReason::Partial) => "อ่านได้บางส่วน ไม่ครบ",
        (Lang::En, UnmeasuredReason::BudgetSpent) => {
            "this program stopped reading before it finished"
        }
        (Lang::Th, UnmeasuredReason::BudgetSpent) => "โปรแกรมนี้หยุดอ่านก่อนจะครบ",
        (Lang::En, UnmeasuredReason::ReadFailed) => "this could not be read",
        (Lang::Th, UnmeasuredReason::ReadFailed) => "อ่านข้อมูลนี้ไม่ได้",
        (Lang::En, UnmeasuredReason::CollectorUnavailable) => "this build does not read that",
        (Lang::Th, UnmeasuredReason::CollectorUnavailable) => "build นี้ยังไม่ได้อ่านส่วนนี้",
    }
}

/// SS-mode consent question.
///
/// It names every kind of thing the scan reads, in the words `PRIVACY.md` uses. Until 0.2.0 the scan
/// read machine settings and nothing else, and the question said so; the collectors that followed
/// widened the scan and left the question describing the old one, which is consent to a different
/// check. `consent_names_every_kind_of_source` keeps the list from going stale quietly again.
pub fn consent(lang: Lang) -> String {
    match lang {
        Lang::En => "SS mode — screenshare check\n\
            This program will read, on this PC:\n\
            \x20 - security settings such as Secure Boot (as Windows and as the firmware report it), memory integrity, and the PowerShell logging policies of this PC and of the Windows account running the scan\n\
            \x20 - the programs running now, and the files in FiveM's plugin folders for GTA V Legacy and Enhanced and FiveM.exe itself, with their signatures (Authenticode)\n\
            \x20 - for FiveM's log, crash and cache folders for GTA V Legacy and Enhanced: how many files and subfolders each holds, their total size and the earliest and latest file times, and for each Enhanced server cache folder when it was created and last changed and how many entries it holds, never a file or folder name; these times can match two reports of this PC\n\
            \x20 - what Windows recorded about programs that ran (Prefetch, BAM, Program Compatibility Assistant), and whether Prefetch is switched on\n\
            \x20 - how many events of each kind the Windows event logs hold, not what the events say, and which file and size Windows sets for each log\n\
            \x20 - whether a Prefetch or event log file is marked read-only\n\
            \x20 - how many records the change journal of the Windows drive holds and when the oldest and newest were written, and for the Prefetch, event log and Program Compatibility Assistant folders and FiveM's plugin folders, how many records name each folder and how many of those created, deleted, renamed or changed a file, never a file name\n\
            \x20 - the drivers registered with Windows: each driver service's name and start setting, where its file is, and that file's SHA-256\n\
            \x20 - when Windows last started, which is shown to staff as one time at the top of the report\n\
            It shows only what matches a rule. Its own code sends nothing anywhere. Your user name is hidden in paths.\n\
            You may refuse.\n\
            Continue? [y/N] "
            .to_owned(),
        Lang::Th => "โหมด SS — ตรวจระหว่างแชร์หน้าจอ\n\
            โปรแกรมจะอ่านข้อมูลเหล่านี้บนเครื่องนี้:\n\
            \x20 - การตั้งค่าความปลอดภัย เช่น Secure Boot (ทั้งตามที่ Windows และเฟิร์มแวร์รายงาน) memory integrity และนโยบายการบันทึกของ PowerShell ทั้งของเครื่องและของบัญชี Windows ที่ใช้รันการสแกน\n\
            \x20 - โปรแกรมที่กำลังรันอยู่ ไฟล์ในโฟลเดอร์ plugin ของ FiveM ทั้ง GTA V Legacy และ Enhanced และตัว FiveM.exe พร้อมลายเซ็นของไฟล์ (Authenticode)\n\
            \x20 - โฟลเดอร์ log, crash และ cache ของ FiveM ทั้ง GTA V Legacy และ Enhanced: จำนวนไฟล์และโฟลเดอร์ย่อย ขนาดรวม และเวลาของไฟล์ที่เก่าสุดกับใหม่สุด และสำหรับโฟลเดอร์ cache ของแต่ละเซิร์ฟเวอร์ใน Enhanced เวลาที่สร้างกับเวลาที่แก้ไขล่าสุด และจำนวนรายการข้างใน โดยไม่เก็บชื่อไฟล์หรือชื่อโฟลเดอร์ เวลาเหล่านี้ทำให้จับคู่รายงานสองฉบับจากเครื่องเดียวกันได้\n\
            \x20 - สิ่งที่ Windows บันทึกไว้เกี่ยวกับโปรแกรมที่เคยรัน (Prefetch, BAM, Program Compatibility Assistant) และ Prefetch เปิดอยู่หรือไม่\n\
            \x20 - จำนวน event แต่ละแบบใน event log ของ Windows โดยไม่อ่านว่า event นั้นเขียนว่าอะไร และไฟล์กับขนาดที่ Windows ตั้งไว้ให้ log แต่ละตัว\n\
            \x20 - ไฟล์ Prefetch หรือไฟล์ event log ถูกตั้งเป็นอ่านอย่างเดียวหรือไม่\n\
            \x20 - จำนวน record ใน change journal ของไดรฟ์ Windows และเวลาของ record เก่าสุดกับใหม่สุด และสำหรับโฟลเดอร์ Prefetch, event log, Program Compatibility Assistant และโฟลเดอร์ plugin ของ FiveM ว่ามี record ที่อ้างถึงแต่ละโฟลเดอร์กี่รายการ และในนั้นเป็นการสร้าง ลบ เปลี่ยนชื่อ หรือแก้ไขไฟล์กี่รายการ โดยไม่เก็บชื่อไฟล์\n\
            \x20 - ไดรเวอร์ที่ลงทะเบียนไว้กับ Windows: ชื่อและการตั้งค่าการเริ่มทำงานของ driver service แต่ละตัว ตำแหน่งไฟล์ และ SHA-256 ของไฟล์นั้น\n\
            \x20 - เวลาที่ Windows เริ่มทำงานครั้งล่าสุด ซึ่งแอดมินจะเห็นเป็นเวลาเดียวที่ด้านบนของรายงาน\n\
            แสดงเฉพาะสิ่งที่ตรง rule โค้ดของโปรแกรมไม่ส่งอะไรออกไปไหน ชื่อผู้ใช้ใน path จะถูกซ่อน\n\
            คุณปฏิเสธได้\n\
            ดำเนินการต่อ? [y/N] "
            .to_owned(),
    }
}

/// Line shown before an elevated copy waits for Enter, so its window does not close on the report.
pub fn pause_at_exit(lang: Lang) -> &'static str {
    text(lang, "pause_at_exit")
}

/// Message printed when consent is refused.
pub fn declined(lang: Lang) -> &'static str {
    text(lang, "declined")
}

/// Message printed once the elevated restart has been requested.
#[cfg(windows)]
pub fn elevate_started(lang: Lang) -> &'static str {
    text(lang, "elevate_started")
}

/// Message printed when the Windows consent prompt was dismissed.
#[cfg(windows)]
pub fn elevate_declined(lang: Lang) -> &'static str {
    text(lang, "elevate_declined")
}

/// Context added to the error when Windows refused to start the elevated program.
#[cfg(windows)]
pub fn elevate_failed(lang: Lang) -> &'static str {
    text(lang, "elevate_failed")
}

/// Message printed when `--elevate` is used on something other than Windows.
#[cfg(not(windows))]
pub fn elevate_not_windows(lang: Lang) -> &'static str {
    text(lang, "elevate_not_windows")
}

/// Renders a view as text.
pub fn render(view: &ReportView, bundle: &Bundle, lang: Lang) -> String {
    let mut out = String::new();
    let header = &view.header;
    let provenance = &header.provenance;

    let _ = writeln!(out, "aeterna-rongroi {}", provenance.version);
    if provenance.official {
        let _ = writeln!(out, "{}", text(lang, "official"));
    } else {
        let _ = writeln!(out, "!! {UNOFFICIAL} — {}", text(lang, "unofficial"));
    }
    let elevated = match header.elevated {
        Some(true) => text(lang, "elevated_yes"),
        Some(false) => text(lang, "elevated_no"),
        None => text(lang, "elevated_unknown"),
    };
    let mode = match view.mode {
        Mode::SelfCheck => "self",
        Mode::Ss => "ss",
    };
    let platform = match &header.os_build {
        Some(build) => format!("{} {build}", header.platform),
        None => header.platform.clone(),
    };
    let _ = writeln!(
        out,
        "mode: {mode} · {platform} · {elevated} · rules: {} ({})",
        header.rules_bundle.rule_count,
        short(&header.rules_bundle.sha256),
    );
    if let Some(sha) = &provenance.exe_sha256 {
        let _ = writeln!(out, "exe sha256: {sha}");
    }
    let _ = writeln!(out, "{}", boot_time_line(&header.boot_time, lang));
    // Above the evidence, because it is a fact about the scan and not about the machine, and
    // because a reviewer who has made up their mind by the third row never reaches a footer
    // (ADR 0027).
    for (count, key) in [
        (view.scope.not_admin, "scope_not_admin"),
        (view.scope.not_attempted, "scope_not_attempted"),
    ] {
        if count > 0 {
            let _ = writeln!(
                out,
                "{}",
                text(lang, key).replace("{n}", &count.to_string())
            );
        }
    }
    let _ = writeln!(
        out,
        "{}",
        text(lang, "listed")
            .replace("{found}", &view.listed.found.to_string())
            .replace("{not_found}", &view.listed.not_found.to_string())
            .replace("{unmeasured}", &view.listed.unmeasured.to_string())
    );
    out.push('\n');

    out.push_str(&evidence_section(view, bundle, lang));

    // Both sections come after the evidence and clearly apart from it, in this order.
    out.push_str(&own_traces_section(view, lang));
    out.push_str(&unmatched_section(view, lang));

    if view.mode == Mode::Ss {
        let _ = writeln!(
            out,
            "\n{}: {} {} · {} {} · {} {} · {} {}",
            text(lang, "hidden"),
            text(lang, "not_found"),
            view.hidden.not_found,
            text(lang, "unmeasured_expected"),
            view.hidden.unmeasured_expected,
            text(lang, "unmeasured_unexpected"),
            view.hidden.unmeasured_unexpected,
            text(lang, "unmatched"),
            view.hidden.unmatched
        );
    }
    let code = if provenance.code_commit().is_some() {
        "code"
    } else {
        "code_unknown"
    };
    let _ = writeln!(
        out,
        "\n{}",
        text(lang, code).replace("{url}", &provenance.code_url())
    );
    let _ = writeln!(out, "{}", text(lang, "footer"));
    out
}

/// The one line of context that says when Windows last started counting (ADR 0039).
fn boot_time_line(boot_time: &BootTime, lang: Lang) -> String {
    match boot_time {
        BootTime::Measured {
            booted_at,
            seconds_since_boot,
        } => text(lang, "boot_time")
            .replace("{at}", booted_at)
            .replace("{since}", &elapsed(*seconds_since_boot, lang)),
        BootTime::Unmeasured { reason: why } => {
            text(lang, "boot_time_unmeasured").replace("{reason}", reason(lang, *why))
        }
    }
}

/// Whole seconds as days, hours and minutes; days only when there is at least one.
fn elapsed(seconds: u64, lang: Lang) -> String {
    let days = seconds / 86_400;
    let hours = seconds % 86_400 / 3_600;
    let minutes = seconds % 3_600 / 60;
    match (lang, days) {
        (Lang::En, 0) => format!("{hours}h {minutes}m"),
        (Lang::En, _) => format!("{days}d {hours}h {minutes}m"),
        (Lang::Th, 0) => format!("{hours} ชม. {minutes} นาที"),
        (Lang::Th, _) => format!("{days} วัน {hours} ชม. {minutes} นาที"),
    }
}

/// The evidence, one entry at a time, each with the rule's own text.
fn evidence_section(view: &ReportView, bundle: &Bundle, lang: Lang) -> String {
    let mut out = String::new();
    // A rule title states what the rule looks for, not what was seen; say so for every state.
    let check = match lang {
        Lang::En => "check",
        Lang::Th => "ตรวจ",
    };
    for evidence in &view.evidence {
        let rule_text = bundle.text(&evidence.rule_id, lang.code());
        let title = rule_text
            .as_ref()
            .map_or_else(|| evidence.rule_id.clone(), |t| t.title.clone());
        let (label, detail) = match &evidence.state {
            EvidenceState::Found { observations } => {
                let fields = observations
                    .iter()
                    .flat_map(|o| o.fields.iter().map(|(k, v)| format!("{k}={}", plain(v))))
                    .collect::<Vec<_>>()
                    .join(", ");
                (text(lang, "found"), fields)
            }
            // The report keeps the English source text; the rule text carries the translation.
            EvidenceState::NotFound { retention } => (
                text(lang, "not_found"),
                rule_text
                    .as_ref()
                    .map_or_else(|| retention.clone(), |t| t.retention.clone()),
            ),
            EvidenceState::Unmeasured {
                reason: why,
                expected,
            } => {
                // A reason the rule itself named is a different statement from one it did not, and
                // a reader cannot tell them apart from the reason alone (ADR 0027).
                let label = if *expected {
                    text(lang, "unmeasured_expected")
                } else {
                    text(lang, "unmeasured_unexpected")
                };
                (label, reason(lang, *why).to_owned())
            }
        };
        let _ = writeln!(
            out,
            "[{label}] {check}: {title}  ({}, {})",
            evidence.strength.as_str(),
            evidence.collector
        );
        if !detail.is_empty() {
            let _ = writeln!(out, "    {detail}");
        }
        // What the rule means and what it does not prove, beside every state; what legitimately
        // produces the same evidence, beside a match only. Both are mandatory in every rule and
        // neither reached a screen before (ADR 0027).
        if let Some(rule_text) = &rule_text {
            if !rule_text.description.is_empty() {
                let _ = writeln!(
                    out,
                    "    {}: {}",
                    text(lang, "description"),
                    rule_text.description
                );
            }
            if matches!(evidence.state, EvidenceState::Found { .. })
                && !rule_text.falsepositives.is_empty()
            {
                let _ = writeln!(out, "    {}:", text(lang, "falsepositives"));
                for cause in &rule_text.falsepositives {
                    let _ = writeln!(out, "      - {cause}");
                }
            }
        }
    }
    out
}

/// One observation as `field=value, field=value`, the way both trailing sections list it.
fn fields_of(observation: &Observation) -> String {
    observation
        .fields
        .iter()
        .map(|(k, v)| format!("{k}={}", plain(v)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What this program itself left in what the collectors saw. Shown in both modes (ADR 0010).
fn own_traces_section(view: &ReportView, lang: Lang) -> String {
    let mut out = String::new();
    if view.own_traces.is_empty() {
        return out;
    }
    let _ = writeln!(
        out,
        "\n{} — {}",
        text(lang, "own_traces"),
        text(lang, "own_traces_note")
    );
    for entry in &view.own_traces {
        let _ = writeln!(
            out,
            "    [{}] {}",
            entry.collector,
            fields_of(&entry.observation)
        );
    }
    out
}

/// What the collectors saw that no rule matched. Self mode lists these; in SS mode the list arrives
/// empty and they appear only as a number in the hidden line (ADR 0014).
fn unmatched_section(view: &ReportView, lang: Lang) -> String {
    let mut out = String::new();
    if view.unmatched.is_empty() {
        return out;
    }
    let _ = writeln!(
        out,
        "\n{} — {}",
        text(lang, "unmatched"),
        text(lang, "unmatched_note")
    );
    for group in &view.unmatched {
        for observation in &group.observations {
            let _ = writeln!(out, "    [{}] {}", group.collector, fields_of(observation));
        }
    }
    out
}

fn plain(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn short(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

#[cfg(test)]
mod tests {
    use rongroi_core::model::{
        Evidence, EvidenceState, Mode, Observation, OwnTraceEntry, REPORT_SCHEMA_VERSION, Report,
        ReportHeader, Strength, UnmatchedGroup,
    };
    use rongroi_core::provenance::Provenance;
    use rongroi_core::rules::Rule;
    use rongroi_core::view;

    use super::*;

    /// The rule these tests build a report around.
    ///
    /// Looked up by path, not taken as `rules()[0]`: the report below fabricates a
    /// `secure_boot=disabled` observation and asserts this rule's own Thai `retention`, so it is
    /// this rule the tests mean and not whichever one sorts first. Index 0 was that rule until
    /// `rules/evtx/` existed, which is the kind of coupling a new rule is not supposed to break.
    fn subject(bundle: &Bundle) -> &Rule {
        &bundle
            .rules()
            .iter()
            .find(|sourced| sourced.path == "posture/boot/secure-boot-disabled/rule.yaml")
            .expect("the secure-boot rule is in the embedded bundle")
            .rule
    }

    fn report(official: bool) -> (Report, Bundle) {
        let bundle = Bundle::embedded().unwrap();
        let rule = subject(&bundle);
        let header = ReportHeader {
            schema_version: REPORT_SCHEMA_VERSION,
            provenance: Provenance::from_parts(official.then_some("1"), "0.0.0-test", None, None),
            rules_bundle: bundle.info().clone(),
            platform: "windows".to_owned(),
            os_build: Some("26100".to_owned()),
            elevated: Some(false),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            boot_time: rongroi_core::model::BootTime::Measured {
                booted_at: "2025-12-28T21:56:56Z".to_owned(),
                seconds_since_boot: 266_584,
            },
            profiles_directory: None,
        };
        let evidence = Evidence {
            rule_id: rule.id.clone(),
            collector: rule.collector.clone(),
            strength: Strength::Posture,
            state: EvidenceState::Found {
                observations: vec![Observation {
                    collector: "posture".to_owned(),
                    fields: [(
                        "secure_boot".to_owned(),
                        serde_json::Value::from("disabled"),
                    )]
                    .into(),
                }],
            },
        };
        (
            Report {
                header,
                evidence: vec![evidence],
                own_traces: Vec::new(),
                unmatched: Vec::new(),
            },
            bundle,
        )
    }

    #[test]
    fn unofficial_build_is_announced() {
        let (report, bundle) = report(false);
        let text = render(&view::for_mode(&report, Mode::SelfCheck), &bundle, Lang::En);
        assert!(text.contains("UNOFFICIAL BUILD"), "{text}");
        let thai = render(&view::for_mode(&report, Mode::SelfCheck), &bundle, Lang::Th);
        assert!(thai.contains("UNOFFICIAL BUILD"), "{thai}");
    }

    /// One line above the evidence, in both modes and both languages, carrying the caveat that stops
    /// a start days ago being read as something the player did (ADR 0039).
    #[test]
    fn the_boot_time_is_one_line_of_context_above_the_evidence() {
        let (report, bundle) = report(false);
        for mode in [Mode::SelfCheck, Mode::Ss] {
            let text = render(&view::for_mode(&report, mode), &bundle, Lang::En);
            let (above, below) = text
                .split_once("[FOUND]")
                .expect("the evidence is rendered");
            let lines: Vec<&str> = above
                .lines()
                .filter(|line| line.starts_with("Windows start:"))
                .collect();
            assert_eq!(lines.len(), 1, "{text}");
            assert!(
                lines[0].contains("2025-12-28T21:56:56Z, 3d 2h 3m before this scan"),
                "{text}"
            );
            assert!(lines[0].contains("Fast Startup"), "{text}");
            assert!(!below.contains("Windows start"), "{text}");

            let thai = render(&view::for_mode(&report, mode), &bundle, Lang::Th);
            assert!(
                thai.contains("Windows เริ่มทำงาน: 2025-12-28T21:56:56Z"),
                "{thai}"
            );
            assert!(thai.contains("3 วัน 2 ชม. 3 นาที"), "{thai}");
            assert!(thai.contains("Fast Startup"), "{thai}");
        }
    }

    /// No time is printed where none was measured, and the reason uses the words every other
    /// unmeasured result uses.
    #[test]
    fn an_unmeasured_boot_time_says_why_and_prints_no_time() {
        let (mut report, bundle) = report(false);
        report.header.boot_time = rongroi_core::model::BootTime::Unmeasured {
            reason: UnmeasuredReason::NotWindows,
        };
        let text = render(&view::for_mode(&report, Mode::SelfCheck), &bundle, Lang::En);
        assert!(
            text.contains("Windows start: not measured — not running on Windows"),
            "{text}"
        );
        assert!(!text.contains("before this scan"), "{text}");
    }

    #[test]
    fn elapsed_time_leaves_out_days_when_there_are_none() {
        assert_eq!(elapsed(0, Lang::En), "0h 0m");
        assert_eq!(elapsed(59, Lang::En), "0h 0m");
        assert_eq!(elapsed(32_571, Lang::En), "9h 2m");
        assert_eq!(elapsed(86_400, Lang::En), "1d 0h 0m");
        assert_eq!(elapsed(32_571, Lang::Th), "9 ชม. 2 นาที");
    }

    #[test]
    fn official_build_has_no_banner() {
        let (report, bundle) = report(true);
        let text = render(&view::for_mode(&report, Mode::SelfCheck), &bundle, Lang::En);
        assert!(!text.contains("UNOFFICIAL BUILD"), "{text}");
    }

    #[test]
    fn thai_uses_translated_rule_title_and_ss_shows_hidden_counts() {
        let (report, bundle) = report(false);
        let text = render(&view::for_mode(&report, Mode::Ss), &bundle, Lang::Th);
        assert!(text.contains("Secure Boot ถูกปิดอยู่"), "{text}");
        assert!(text.contains("ซ่อนในโหมด SS"), "{text}");
        assert!(text.contains("พิสูจน์ไม่ได้ว่าเครื่องสะอาด"), "{text}");
    }

    /// What the tool itself left in what the collectors saw is listed apart from the evidence and
    /// said to be excluded, so that a reader cannot mistake it for something found on the PC.
    /// Every collector in this build is named in the consent question, in both languages. The
    /// words are keyed by collector id and the ids are compared with `rongroi_collectors::all()`, so
    /// adding a collector without saying so here fails this test rather than widening what a player
    /// agreed to without telling them.
    #[test]
    fn consent_names_every_kind_of_source() {
        let named: &[(&str, &[&str])] = &[
            ("bam", &["BAM"]),
            ("driver_service", &["driver"]),
            ("evtx", &["event log"]),
            (
                "fivem_dir",
                &[
                    "FiveM",
                    "plugin",
                    "Legacy",
                    "Enhanced",
                    "FiveM.exe",
                    "Authenticode",
                ],
            ),
            ("pca", &["Program Compatibility Assistant"]),
            (
                "posture",
                &["Secure Boot", "memory integrity", "PowerShell"],
            ),
            ("prefetch", &["Prefetch"]),
            ("process", &[]),
            ("usn", &["change journal"]),
        ];
        let mut ids: Vec<&str> = rongroi_collectors::all().iter().map(|c| c.id()).collect();
        ids.sort_unstable();
        let listed: Vec<&str> = named.iter().map(|(id, _)| *id).collect();
        assert_eq!(
            ids, listed,
            "a collector was added or removed; say what it reads in `consent`"
        );
        // Not a collector, so not in the list above: the report header's boot time is a new read of
        // its own, and a player agrees to it like any other (ADR 0039).
        let running = [
            (
                Lang::En,
                "programs running now",
                "when Windows last started",
                [
                    "read-only",
                    "size Windows sets",
                    "Windows account running the scan",
                ],
            ),
            (
                Lang::Th,
                "โปรแกรมที่กำลังรันอยู่",
                "เวลาที่ Windows เริ่มทำงานครั้งล่าสุด",
                [
                    "อ่านอย่างเดียว",
                    "ขนาดที่ Windows ตั้งไว้",
                    "บัญชี Windows ที่ใช้รันการสแกน",
                ],
            ),
        ];
        for (lang, process_words, boot_time_words, later_reads) in running {
            let question = consent(lang);
            assert!(question.contains(process_words), "{question}");
            assert!(question.contains(boot_time_words), "{question}");
            for words in later_reads {
                assert!(question.contains(words), "{words} missing from {question}");
            }
            for word in named.iter().flat_map(|(_, words)| words.iter()) {
                assert!(question.contains(word), "{word} missing from {question}");
            }
        }
    }

    #[test]
    fn own_traces_are_rendered_in_their_own_section() {
        let (mut report, bundle) = report(false);
        report.own_traces = vec![OwnTraceEntry {
            collector: "process".to_owned(),
            observation: Observation {
                collector: "process".to_owned(),
                fields: [
                    (
                        "name".to_owned(),
                        serde_json::Value::from("aeterna-rongroi.exe"),
                    ),
                    (
                        "path".to_owned(),
                        serde_json::Value::from(r"C:\Users\a\aeterna-rongroi.exe"),
                    ),
                ]
                .into(),
            },
        }];
        let view = view::for_mode(&report, Mode::SelfCheck);
        let text = render(&view, &bundle, Lang::En);

        let (above, section) = text
            .split_once("own traces (excluded)")
            .expect("the own-traces section is announced");
        // Nothing about the tool's own process appears among the evidence above it.
        assert!(!above.contains("aeterna-rongroi.exe"), "{above}");
        assert!(section.contains("aeterna-rongroi.exe"), "{section}");
        assert!(
            section.contains(r"C:\Users\a\aeterna-rongroi.exe"),
            "{section}"
        );

        let thai = render(&view, &bundle, Lang::Th);
        assert!(thai.contains("ร่องรอยของโปรแกรมนี้เอง"), "{thai}");
    }

    /// A plugin file the `fivem_dir` collector saw, written here as an unmatched observation. Rules read
    /// that collector since ADR 0036; what this test needs is an entry in the bucket, not a real match.
    fn plugin_file() -> Vec<UnmatchedGroup> {
        vec![UnmatchedGroup {
            collector: "fivem_dir".to_owned(),
            observations: vec![Observation {
                collector: "fivem_dir".to_owned(),
                fields: [(
                    "path".to_owned(),
                    serde_json::Value::from(
                        r"C:\Users\a\AppData\Local\FiveM\FiveM.app\plugins\overlay.dll",
                    ),
                )]
                .into(),
            }],
        }]
    }

    /// What the collectors saw that no rule matched is listed after the evidence and after the own
    /// traces, in a section of its own that says these are not findings (ADR 0014).
    #[test]
    fn unmatched_observations_are_rendered_in_their_own_section() {
        let (mut report, bundle) = report(false);
        report.unmatched = plugin_file();
        let view = view::for_mode(&report, Mode::SelfCheck);
        let text = render(&view, &bundle, Lang::En);

        let (above, section) = text
            .split_once("unmatched observations")
            .expect("the unmatched section is announced");
        // Nothing about the file appears among the evidence above it.
        assert!(!above.contains("overlay.dll"), "{above}");
        assert!(section.contains("overlay.dll"), "{section}");
        assert!(section.contains("fivem_dir"), "{section}");

        let thai = render(&view, &bundle, Lang::Th);
        assert!(thai.contains("ไม่ตรง rule ใดเลย"), "{thai}");
    }

    /// SS mode says how many there were and names none of them: a raw listing of what a collector
    /// saw is exactly what that mode promises not to show (ADR 0014).
    #[test]
    fn ss_mode_counts_unmatched_observations_without_listing_them() {
        let (mut report, bundle) = report(false);
        report.unmatched = plugin_file();
        let text = render(&view::for_mode(&report, Mode::Ss), &bundle, Lang::En);
        assert!(!text.contains("overlay.dll"), "{text}");
        assert!(text.contains("unmatched observations 1"), "{text}");
    }

    #[test]
    fn no_unmatched_section_when_every_observation_matched_a_rule() {
        let (report, bundle) = report(false);
        let text = render(&view::for_mode(&report, Mode::SelfCheck), &bundle, Lang::En);
        assert!(!text.contains("unmatched observations"), "{text}");
    }

    /// A match shown without what else produces it is a match shown as an accusation. Both halves
    /// are mandatory in every rule, both are translated, and neither reached a screen before
    /// (NIST SP 800-86 section 3.4, ADR 0027).
    #[test]
    fn a_found_entry_shows_its_description_and_its_false_positives() {
        let (report, bundle) = report(false);
        let rule = subject(&bundle);
        let view = view::for_mode(&report, Mode::SelfCheck);

        let english = render(&view, &bundle, Lang::En);
        assert!(english.contains("About this check"), "{english}");
        assert!(english.contains(&rule.description), "{english}");
        assert!(
            english.contains("Ordinary things that also produce this"),
            "{english}"
        );
        for cause in &rule.falsepositives {
            assert!(english.contains(cause), "{english}");
        }

        let thai = render(&view, &bundle, Lang::Th);
        let translated = bundle.text(&rule.id, "th").expect("the rule is translated");
        assert!(thai.contains("เกี่ยวกับการตรวจนี้"), "{thai}");
        assert!(thai.contains(&translated.description), "{thai}");
        for cause in &translated.falsepositives {
            assert!(thai.contains(cause), "{thai}");
        }
        // The English text is not shown alongside it.
        assert!(!thai.contains(&rule.description), "{thai}");
    }

    /// `description` says what the check is, which a reader needs whatever the answer was.
    /// `falsepositives` explains a match, and nothing matched here, so there is nothing to explain.
    #[test]
    fn a_not_found_entry_shows_the_description_and_not_the_false_positives() {
        let (mut report, bundle) = report(false);
        let rule = subject(&bundle).clone();
        report.evidence[0].state = EvidenceState::NotFound {
            retention: rule.retention.clone(),
        };
        let text = render(&view::for_mode(&report, Mode::SelfCheck), &bundle, Lang::En);
        assert!(text.contains(&rule.description), "{text}");
        assert!(
            !text.contains("Ordinary things that also produce this"),
            "{text}"
        );
        for cause in &rule.falsepositives {
            assert!(!text.contains(cause), "{text}");
        }
    }

    /// Two rules that could not be measured for want of administrator rights are one fact about the
    /// scan. It is stated once, above the evidence, and it names the remedy (ADR 0012, ADR 0027).
    #[test]
    fn missing_administrator_rights_is_one_scope_statement_above_the_evidence() {
        let (mut report, bundle) = report(false);
        let first = report.evidence[0].clone();
        report.evidence = vec![first.clone(), first];
        for item in &mut report.evidence {
            item.state = EvidenceState::Unmeasured {
                reason: rongroi_core::model::UnmeasuredReason::NotAdmin,
                expected: false,
            };
        }
        let view = view::for_mode(&report, Mode::SelfCheck);

        let text = render(&view, &bundle, Lang::En);
        let (scope, below) = text
            .split_once("Scope: 2 check(s)")
            .expect("the scope statement is printed once, with the count");
        assert!(scope.contains("mode: self"), "{scope}");
        assert!(!below.contains("Scope: "), "{below}");
        assert!(below.contains("[NOT MEASURED (not expected)]"), "{below}");

        let thai = render(&view, &bundle, Lang::Th);
        assert!(thai.contains("ขอบเขตการตรวจ: มี 2 รายการ"), "{thai}");
    }

    /// A reason the rule named and a reason it did not are different statements, and the reason
    /// alone does not tell them apart (ADR 0027).
    #[test]
    fn an_expected_unmeasured_result_is_labelled_apart_from_an_unexpected_one() {
        let (mut report, bundle) = report(false);
        report.evidence[0].state = EvidenceState::Unmeasured {
            reason: rongroi_core::model::UnmeasuredReason::SourceAbsent,
            expected: true,
        };
        let text = render(&view::for_mode(&report, Mode::SelfCheck), &bundle, Lang::En);
        assert!(text.contains("[NOT MEASURED (expected here)]"), "{text}");
        assert!(!text.contains("(not expected)"), "{text}");
    }

    /// Three counts above the evidence, in both languages, never summed (ADR 0045).
    #[test]
    fn listed_counts_are_one_line_above_the_evidence() {
        let (report, bundle) = report(true);
        for (lang, marker, line) in [
            (
                Lang::En,
                "[FOUND]",
                "Listed: 1 found · 0 not found · 0 not measured",
            ),
            (
                Lang::Th,
                "[เจอ]",
                "รายการที่แสดง: เจอ 1 · ไม่เจอ 0 · ยังไม่ได้วัด 0",
            ),
        ] {
            let text = render(&view::for_mode(&report, Mode::SelfCheck), &bundle, lang);
            let (above, _) = text.split_once(marker).expect("the evidence is rendered");
            assert_eq!(above.lines().filter(|l| *l == line).count(), 1, "{text}");
        }
    }

    #[test]
    fn the_code_link_is_the_commit_of_an_official_build() {
        let (mut report, bundle) = report(true);
        report.header.provenance.commit =
            Some("2c673c54aeb084cd3773057efbb9ed3b98fd2dbc".to_owned());
        let text = render(&view::for_mode(&report, Mode::Ss), &bundle, Lang::En);
        let (before_footer, _) = text.split_once("Evidence only.").expect("footer");
        assert!(
            before_footer.contains(
                "\nCode: https://github.com/aeterna/aeterna-rongroi/tree/2c673c54aeb084cd3773057efbb9ed3b98fd2dbc\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn an_unofficial_build_links_the_repository_and_says_its_code_is_not_known() {
        let (report, bundle) = report(false);
        let text = render(&view::for_mode(&report, Mode::SelfCheck), &bundle, Lang::En);
        assert!(
            text.contains(
                "Code: https://github.com/aeterna/aeterna-rongroi (the code this build was made from is not known)"
            ),
            "{text}"
        );
        assert!(!text.contains("/tree/"), "{text}");
        let thai = render(&view::for_mode(&report, Mode::SelfCheck), &bundle, Lang::Th);
        assert!(
            thai.contains(
                "โค้ด: https://github.com/aeterna/aeterna-rongroi (ไม่รู้ว่า build นี้สร้างจากโค้ดของ commit ไหน)"
            ),
            "{thai}"
        );
    }

    #[test]
    fn not_found_retention_is_shown_in_the_chosen_language() {
        let (mut report, bundle) = report(false);
        let english = subject(&bundle).retention.clone();
        report.evidence[0].state = EvidenceState::NotFound {
            retention: english.clone(),
        };
        let view = view::for_mode(&report, Mode::SelfCheck);

        let thai = render(&view, &bundle, Lang::Th);
        assert!(thai.contains("เป็นค่าที่ตั้งไว้ตอนนี้เท่านั้น"), "{thai}");
        assert!(!thai.contains(&english), "{thai}");

        let text = render(&view, &bundle, Lang::En);
        assert!(text.contains(&english), "{text}");
    }
}
