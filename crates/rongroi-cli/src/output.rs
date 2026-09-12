// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Text output of the CLI in English and Thai.

use std::fmt::Write as _;

use clap::ValueEnum;
use rongroi_core::bundle::Bundle;
use rongroi_core::model::{EvidenceState, Mode, UnmeasuredReason};
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
        (Lang::En, "unmeasured") => "NOT MEASURED",
        (Lang::Th, "unmeasured") => "ยังไม่ได้วัด",
        (Lang::En, "hidden") => "Hidden in SS mode",
        (Lang::Th, "hidden") => "ซ่อนในโหมด SS",
        (Lang::En, "footer") => "Evidence only. This report cannot prove that a PC is clean.",
        (Lang::Th, "footer") => "เป็นหลักฐานประกอบเท่านั้น รายงานนี้พิสูจน์ไม่ได้ว่าเครื่องสะอาด",
        (Lang::En, "elevated_yes") => "administrator",
        (Lang::Th, "elevated_yes") => "สิทธิ์ผู้ดูแลระบบ",
        (Lang::En, "elevated_no") => "standard user",
        (Lang::Th, "elevated_no") => "ผู้ใช้ทั่วไป",
        (_, "elevated_unknown") => "?",
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
        (Lang::Th, "elevate_not_windows") => "สิทธิ์ผู้ดูแลระบบเป็นเรื่องของ Windows --elevate ไม่มีผลบนระบบนี้",
        _ => "",
    }
}

fn reason(lang: Lang, reason: UnmeasuredReason) -> &'static str {
    match (lang, reason) {
        (Lang::En, UnmeasuredReason::NotWindows) => "not running on Windows",
        (Lang::Th, UnmeasuredReason::NotWindows) => "ไม่ได้รันบน Windows",
        (Lang::En, UnmeasuredReason::NotOnThisOs) => "not available on this Windows version",
        (Lang::Th, UnmeasuredReason::NotOnThisOs) => "ไม่มีใน Windows รุ่นนี้",
        (Lang::En, UnmeasuredReason::NotAdmin) => "needs administrator rights",
        (Lang::Th, UnmeasuredReason::NotAdmin) => "ต้องใช้สิทธิ์ผู้ดูแลระบบ",
        (Lang::En, UnmeasuredReason::AccessDenied) => "Windows denied access",
        (Lang::Th, UnmeasuredReason::AccessDenied) => "Windows ไม่อนุญาตให้อ่าน",
        (Lang::En, UnmeasuredReason::ServiceDisabled) => {
            "the Windows service that records this is off"
        }
        (Lang::Th, UnmeasuredReason::ServiceDisabled) => "บริการของ Windows ที่บันทึกข้อมูลนี้ถูกปิด",
        (Lang::En, UnmeasuredReason::SourceMissing) => "not reported on this PC",
        (Lang::Th, UnmeasuredReason::SourceMissing) => "เครื่องนี้ไม่ได้รายงานข้อมูลนี้",
        (Lang::En, UnmeasuredReason::ReadFailed) => "could not be read",
        (Lang::Th, UnmeasuredReason::ReadFailed) => "อ่านข้อมูลไม่ได้",
        (Lang::En, UnmeasuredReason::CollectorUnavailable) => "not supported by this build",
        (Lang::Th, UnmeasuredReason::CollectorUnavailable) => "build นี้ยังไม่รองรับ",
    }
}

/// SS-mode consent question.
pub fn consent(lang: Lang) -> String {
    match lang {
        Lang::En => "SS mode — screenshare check\n\
            This program will read machine security settings on this PC and show only what matches a rule.\n\
            Its own code sends nothing anywhere. Your user name is hidden in paths.\n\
            You may refuse.\n\
            Continue? [y/N] "
            .to_owned(),
        Lang::Th => "โหมด SS — ตรวจระหว่างแชร์หน้าจอ\n\
            โปรแกรมจะอ่านการตั้งค่าความปลอดภัยของเครื่องนี้ และแสดงเฉพาะสิ่งที่ตรง rule\n\
            โค้ดของโปรแกรมไม่ส่งอะไรออกไปไหน ชื่อผู้ใช้ใน path จะถูกซ่อน\n\
            คุณปฏิเสธได้\n\
            ดำเนินการต่อ? [y/N] "
            .to_owned(),
    }
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
    out.push('\n');

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
                rule_text.map_or_else(|| retention.clone(), |t| t.retention),
            ),
            EvidenceState::Unmeasured { reason: why } => {
                (text(lang, "unmeasured"), reason(lang, *why).to_owned())
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
    }

    if view.mode == Mode::Ss {
        let _ = writeln!(
            out,
            "\n{}: {} {} · {} {}",
            text(lang, "hidden"),
            text(lang, "not_found"),
            view.hidden.not_found,
            text(lang, "unmeasured"),
            view.hidden.unmeasured
        );
    }
    let _ = writeln!(out, "\n{}", text(lang, "footer"));
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
        Evidence, EvidenceState, Mode, Observation, REPORT_SCHEMA_VERSION, Report, ReportHeader,
        Strength,
    };
    use rongroi_core::provenance::Provenance;
    use rongroi_core::view;

    use super::*;

    fn report(official: bool) -> (Report, Bundle) {
        let bundle = Bundle::embedded().unwrap();
        let rule = &bundle.rules()[0].rule;
        let header = ReportHeader {
            schema_version: REPORT_SCHEMA_VERSION,
            provenance: Provenance::from_parts(official.then_some("1"), "0.0.0-test", None, None),
            rules_bundle: bundle.info().clone(),
            platform: "windows".to_owned(),
            os_build: Some("26100".to_owned()),
            elevated: Some(false),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
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

    #[test]
    fn not_found_retention_is_shown_in_the_chosen_language() {
        let (mut report, bundle) = report(false);
        let english = bundle.rules()[0].rule.retention.clone();
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
