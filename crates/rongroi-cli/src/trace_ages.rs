// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The trace-ages section and the cross-source statement as text (ADR 0061).
//!
//! Their words are the desktop's locale files, read here as they are compiled in, so the fixed
//! strings ADR 0061 gives exist once and `cargo xtask check-locales` checks them: the heading, the
//! line forms and the ordinary causes. The core fills in only dates, day counts, counts, the edition
//! and the reason.

use std::fmt::Write as _;

use rongroi_core::bundle::Bundle;
use rongroi_core::model::UnmeasuredReason;
use rongroi_core::view::{
    AnchorAgeState, CrossSourceStatement, SourceLineKind, TraceAge, TraceAgeState, TraceAges,
};

use crate::output::{Lang, reason};

const EN: &str = include_str!("../../../apps/desktop/src/locales/en/report.json");
const TH: &str = include_str!("../../../apps/desktop/src/locales/th/report.json");

/// The desktop's report strings in one language, with English beneath for a key not translated.
pub(crate) struct Words {
    lang: Lang,
    own: serde_json::Value,
    english: serde_json::Value,
}

impl Words {
    /// The strings for `lang`. A file that does not parse gives no strings rather than a panic; the
    /// tests below fail on it.
    pub(crate) fn new(lang: Lang) -> Self {
        let parse = |text: &str| serde_json::from_str(text).unwrap_or(serde_json::Value::Null);
        let own = match lang {
            Lang::En => parse(EN),
            Lang::Th => parse(TH),
        };
        Self {
            lang,
            own,
            english: parse(EN),
        }
    }

    /// The string at the dotted `key`, with each `{{name}}` in it replaced.
    pub(crate) fn get(&self, key: &str, values: &[(&str, &str)]) -> String {
        let find = |root: &serde_json::Value| {
            key.split('.')
                .try_fold(root, |node, part| node.get(part))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let mut text = find(&self.own)
            .or_else(|| find(&self.english))
            .unwrap_or_default();
        for (name, value) in values {
            text = text.replace(&format!("{{{{{name}}}}}"), value);
        }
        text
    }

    /// "3 days", "1 day", "3 วัน".
    fn days(&self, days: i64) -> String {
        let count = days.to_string();
        let key = if days == 1 {
            "trace_ages.days_before_one"
        } else {
            "trace_ages.days_before_other"
        };
        self.get(key, &[("count", &count)])
    }

    fn reason(&self, why: UnmeasuredReason) -> &'static str {
        reason(self.lang, why)
    }
}

/// The trace-ages section: its note, the anchors, each source's row with its ordinary retention, the
/// folded logs, and the ordinary causes once (ADR 0061).
pub(crate) fn section(ages: &TraceAges, bundle: &Bundle, lang: Lang) -> String {
    let words = Words::new(lang);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n{} — {}",
        words.get("trace_ages.title", &[]),
        words.get("trace_ages.note", &[])
    );
    let _ = writeln!(out, "    {}:", words.get("trace_ages.anchors", &[]));
    for anchor in &ages.anchors {
        let kept = match &anchor.state {
            AnchorAgeState::Measured {
                kept: Some(kept), ..
            } => kept.to_string(),
            _ => String::new(),
        };
        let label = words.get(
            &format!("trace_ages.anchor.{}", anchor.anchor),
            &[("kept", &kept)],
        );
        let value = match &anchor.state {
            AnchorAgeState::Measured {
                on, days_before, ..
            } => words.get(
                "trace_ages.on",
                &[("date", on), ("days", &words.days(*days_before))],
            ),
            AnchorAgeState::Unmeasured { reason } => not_read(&words, *reason),
        };
        let _ = writeln!(out, "    - {label}: {value}");
        let _ = writeln!(
            out,
            "      {}",
            words.get(&format!("trace_ages.resets.{}", anchor.anchor), &[])
        );
    }
    let _ = writeln!(out, "    {}:", words.get("trace_ages.sources", &[]));
    let mut previous: Option<&str> = None;
    for (index, row) in ages.rows.iter().enumerate() {
        let _ = writeln!(out, "    - {}", row_line(&words, row));
        let last_of_collector = ages
            .rows
            .get(index + 1)
            .is_none_or(|next| next.collector != row.collector);
        if row.collector == "evtx"
            && last_of_collector
            && let Some(folded) = &ages.folded_logs
        {
            let _ = writeln!(
                out,
                "    - [evtx] {}",
                words.get(
                    "trace_ages.folded",
                    &[
                        ("logs", &folded.logs.to_string()),
                        ("withRecords", &folded.with_records.to_string()),
                        ("notRead", &folded.not_read.to_string()),
                    ]
                )
            );
        }
        if last_of_collector && previous != Some(row.collector.as_str()) {
            previous = Some(row.collector.as_str());
            if let Some(text) = bundle.age_text(&row.collector, lang_code(lang)) {
                let documented = if text.documented {
                    "trace_ages.documented"
                } else {
                    "trace_ages.not_documented"
                };
                let _ = writeln!(
                    out,
                    "      {} ({}; {}: {})",
                    text.retention,
                    words.get(documented, &[]),
                    words.get("trace_ages.references", &[]),
                    text.references.join(", ")
                );
            }
        }
    }
    let _ = writeln!(out, "    {}", words.get("trace_ages.causes_intro", &[]));
    for cause in CAUSES {
        let _ = writeln!(
            out,
            "      - {}",
            words.get(&format!("trace_ages.causes.{cause}"), &[])
        );
    }
    out
}

/// The ordinary causes under the trace-ages section, in the ADR's order.
const CAUSES: [&str; 7] = [
    "reinstall",
    "cleanup",
    "log_size",
    "prefetch_off",
    "fivem_reinstalled",
    "moved",
    "clock",
];

/// The ordinary causes under the statement, in the ADR's order.
const STATEMENT_CAUSES: [&str; 7] = [
    "reinstall",
    "cleanup",
    "prefetch_off",
    "fivem_reinstalled",
    "other_name",
    "windows_removes",
    "clock",
];

fn lang_code(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "en",
        Lang::Th => "th",
    }
}

/// `not_admin` is "not known", never "empty"; `source_absent` and `source_empty` keep their own
/// words, since the place was looked at; every other reason is "not read" and the report's word.
fn not_read(words: &Words, why: UnmeasuredReason) -> String {
    match why {
        UnmeasuredReason::NotAdmin => words.get("trace_ages.not_admin", &[]),
        UnmeasuredReason::SourceAbsent | UnmeasuredReason::SourceEmpty => {
            words.reason(why).to_owned()
        }
        _ => words.get("trace_ages.not_read", &[("reason", words.reason(why))]),
    }
}

fn row_line(words: &Words, row: &TraceAge) -> String {
    let mut name = format!("[{}", row.collector);
    if let Some(place) = &row.place {
        let _ = write!(
            name,
            " {}",
            words.get(&format!("trace_ages.place.{place}"), &[])
        );
    }
    if let Some(subject) = &row.subject {
        let _ = write!(name, " {subject}");
    }
    name.push(']');
    match &row.state {
        TraceAgeState::Unmeasured { reason } => format!("{name} {}", not_read(words, *reason)),
        TraceAgeState::Measured {
            oldest,
            days_before,
            count,
            extra,
        } => {
            let mut parts = Vec::new();
            match (oldest, days_before) {
                (Some(at), Some(days)) => parts.push(words.get(
                    "trace_ages.oldest",
                    &[("at", at), ("days", &words.days(*days))],
                )),
                _ => parts.push(words.get("trace_ages.holds_nothing", &[])),
            }
            let count_key = match row.place.as_deref() {
                Some("enhanced_server_cache") => "enhanced_server_cache",
                _ => row.collector.as_str(),
            };
            parts.push(words.get(
                &format!("trace_ages.count.{count_key}"),
                &[("count", &count.to_string())],
            ));
            for (field, value) in extra {
                let value = value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned);
                parts.push(words.get(&format!("trace_ages.extra.{field}"), &[("value", &value)]));
            }
            format!("{name} {}", parts.join(", "))
        }
    }
}

/// The cross-source statement: its heading, `FiveM`'s line, one line per record, and the ordinary
/// causes, always in full (ADR 0061 section 3).
pub(crate) fn statement(statements: &[CrossSourceStatement], lang: Lang) -> String {
    let words = Words::new(lang);
    let mut out = String::new();
    for statement in statements {
        let _ = writeln!(out, "\n{}", words.get("cross_source.title", &[]));
        let fivem = &statement.fivem;
        let mut first = if fivem.editions.is_empty() {
            words.get("cross_source.absent", &[])
        } else {
            let editions: Vec<String> = fivem
                .editions
                .iter()
                .map(|edition| words.get(&format!("cross_source.edition.{edition}"), &[]))
                .collect();
            words.get(
                "cross_source.present",
                &[("editions", &editions.join(", "))],
            )
        };
        if let (Some(date), Some(days)) = (&fivem.folders_written, fivem.folders_days_before) {
            first.push(' ');
            first.push_str(&words.get(
                "cross_source.folders_written",
                &[("date", date), ("days", &words.days(days))],
            ));
        }
        if let (true, Some(date)) = (fivem.server_folders > 0, &fivem.servers_written) {
            first.push(' ');
            first.push_str(&words.get(
                "cross_source.servers",
                &[("count", &fivem.server_folders.to_string()), ("date", date)],
            ));
        }
        let _ = writeln!(out, "    {}: {first}", words.get("cross_source.fivem", &[]));
        let mut named = false;
        for source in &statement.sources {
            let line = match &source.line {
                SourceLineKind::Selected { entries, latest } => words.get(
                    "cross_source.selected",
                    &[("count", &entries.to_string()), ("date", latest)],
                ),
                SourceLineKind::NoEntry {
                    entries,
                    oldest,
                    days_before,
                } => {
                    // The names once, on the first line that needs them; "those names" after.
                    let key = if named {
                        "cross_source.no_entry"
                    } else {
                        "cross_source.no_entry_named"
                    };
                    named = true;
                    words.get(
                        key,
                        &[
                            ("count", &entries.to_string()),
                            ("date", oldest),
                            ("days", &words.days(*days_before)),
                        ],
                    )
                }
                SourceLineKind::CouldNotShow { .. } => {
                    words.get("cross_source.could_not_show", &[])
                }
                SourceLineKind::NotRead {
                    reason: UnmeasuredReason::NotAdmin,
                } => words.get("cross_source.not_read_admin", &[]),
                SourceLineKind::NotRead { reason } => words.get(
                    "cross_source.not_read",
                    &[("reason", words.reason(*reason))],
                ),
                SourceLineKind::SwitchedOff => words.get("cross_source.switched_off", &[]),
            };
            let _ = writeln!(
                out,
                "    {}: {line}",
                words.get(&format!("cross_source.source.{}", source.collector), &[])
            );
        }
        let _ = writeln!(out, "    {}", words.get("cross_source.causes_intro", &[]));
        for cause in STATEMENT_CAUSES {
            let _ = writeln!(
                out,
                "      - {}",
                words.get(&format!("cross_source.causes.{cause}"), &[])
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every key this file asks for is in both locale files, so neither language prints an empty
    /// line; and the English heading and first cause are the ADR's words.
    #[test]
    fn every_key_this_text_uses_is_in_both_languages() {
        let mut keys: Vec<String> = [
            "trace_ages.title",
            "trace_ages.note",
            "trace_ages.anchors",
            "trace_ages.sources",
            "trace_ages.on",
            "trace_ages.days_before_one",
            "trace_ages.days_before_other",
            "trace_ages.oldest",
            "trace_ages.holds_nothing",
            "trace_ages.not_admin",
            "trace_ages.not_read",
            "trace_ages.documented",
            "trace_ages.not_documented",
            "trace_ages.references",
            "trace_ages.folded",
            "trace_ages.causes_intro",
            "cross_source.title",
            "cross_source.fivem",
            "cross_source.present",
            "cross_source.absent",
            "cross_source.folders_written",
            "cross_source.servers",
            "cross_source.selected",
            "cross_source.no_entry_named",
            "cross_source.no_entry",
            "cross_source.could_not_show",
            "cross_source.not_read_admin",
            "cross_source.not_read",
            "cross_source.switched_off",
            "cross_source.causes_intro",
        ]
        .map(str::to_owned)
        .to_vec();
        for cause in CAUSES {
            keys.push(format!("trace_ages.causes.{cause}"));
        }
        for cause in STATEMENT_CAUSES {
            keys.push(format!("cross_source.causes.{cause}"));
        }
        for anchor in [
            "boot_time",
            "install_date",
            "setup_earliest_install",
            "usn_journal_created",
            "system_drive_root_created",
            "recycle_bin_created",
            "fivem_legacy_program_folder_created",
            "fivem_legacy_app_folder_created",
            "fivem_enhanced_program_folder_created",
        ] {
            keys.push(format!("trace_ages.anchor.{anchor}"));
            keys.push(format!("trace_ages.resets.{anchor}"));
        }
        for lang in [Lang::En, Lang::Th] {
            let words = Words::new(lang);
            for key in &keys {
                let find = key
                    .split('.')
                    .try_fold(&words.own, |node, part| node.get(part))
                    .and_then(serde_json::Value::as_str);
                assert!(find.is_some_and(|text| !text.is_empty()), "{lang:?}: {key}");
            }
        }
        let english = Words::new(Lang::En);
        assert_eq!(
            english.get("cross_source.title", &[]),
            "FiveM on this PC, beside Windows' records of programs that ran"
        );
        assert_eq!(english.days(1), "1 day");
        assert_eq!(english.days(48), "48 days");
        assert_eq!(Words::new(Lang::Th).days(48), "48 วัน");
    }

    fn render_fixture(host: &str, mode: rongroi_core::model::Mode, lang: Lang) -> String {
        use rongroi_collectors::scan::{self, ScanContext};
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts")
            .join(host);
        let host = rongroi_host::FixtureHost::load(&dir).unwrap();
        let bundle = Bundle::embedded().unwrap();
        let report = scan::run(
            &host,
            &bundle,
            ScanContext {
                provenance: rongroi_core::provenance::Provenance::from_parts(
                    None,
                    "0.0.0-test",
                    None,
                    None,
                ),
                generated_at: "2026-01-01T00:00:00Z".to_owned(),
                self_identity: rongroi_core::engine::SelfIdentity::default(),
                tier: rongroi_core::model::ScanTier::Standard,
            },
        );
        crate::output::render(&rongroi_core::view::for_mode(&report, mode), &bundle, lang)
    }

    /// The statement and the section as a screenshare viewer reads them, in both languages: the
    /// statement's line forms and causes, an anchor with its reset, a row with its retention text.
    #[test]
    fn the_section_and_the_statement_read_as_the_adr_writes_them() {
        use rongroi_core::model::Mode;
        let text = render_fixture("trace-ages-elevated", Mode::Ss, Lang::En);
        for expected in [
            "FiveM on this PC, beside Windows' records of programs that ran",
            "    FiveM: FiveM.exe is present (Legacy). FiveM's own folders were last written 2025-12-30 (1 day before this scan).",
            "    Prefetch: no entry for FiveM.exe, GTA5.exe, GTA5_Enhanced.exe, PlayGTAV.exe or FiveM_b…_GTAProcess.exe. It holds 1 entries; the oldest is from 2016-01-12",
            "    BAM: not read — Windows refused to open this. Whether it holds an entry is not known.",
            "    PCA: 1 entries for those names; the latest is from 2025-12-20.",
            "      - a clock that was changed, so that times from different sources are not on the same clock",
            "How far back the traces reach — How far back each source reaches on this PC",
            "    - Windows installed or last feature-upgraded (InstallDate): 2025-10-21, 72 days before this scan",
            "      Reset by a feature upgrade, a reset or a reinstall",
            "    - Earliest installation date Windows Setup kept (2 kept; not documented by Microsoft): 2018-03-02",
            "(documented; Rests on: https://learn.microsoft.com/",
            "    - [bam] not read — Windows refused to open this",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in\n{text}");
        }
        let limited = render_fixture("trace-ages-limited", Mode::Ss, Lang::Th);
        assert!(
            limited.contains("    - [prefetch] อ่านไม่ได้เพราะไม่มีสิทธิ์ผู้ดูแลระบบ — ไม่รู้"),
            "{limited}"
        );
        assert!(!limited.contains("FiveM ในเครื่องนี้ เทียบกับบันทึก"), "{limited}");
    }
}
