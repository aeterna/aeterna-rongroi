// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The game-window section as text (ADR 0078, P6 decisions 3 to 7): the programs Windows recorded near
//! a `FiveM` session, in Self and SS mode and in both languages. Its words are the desktop's locale
//! files, read through the same loader as the trace-ages section.

use std::fmt::Write as _;

use rongroi_core::model::Mode;
use rongroi_core::view::{
    ClockHistory, GameCandidate, GameSession, GameWindows, IdentityFact, IdentityNotKnownReason,
    TimeFact, WindowCounts,
};

use crate::output::Lang;
use crate::trace_ages::Words;

/// The game-window section (ADR 0078, P6 decisions 3 to 7): its title and intro, each session, the
/// window counts, the clock and install notes, then each candidate with its facts. Nothing when there
/// is no view.
pub fn section(view: Option<&GameWindows>, mode: Mode, lang: Lang) -> String {
    let Some(view) = view else {
        return String::new();
    };
    let words = Words::new(lang);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n{} ({})",
        words.get("game.title", &[]),
        words.get("game.experimental", &[])
    );
    let _ = writeln!(out, "{}", words.get("game.intro", &[]));
    // SS mode says which programs it names and why, before any of them is listed.
    if mode == Mode::Ss {
        let _ = writeln!(out, "{}", words.get("game.ss_rule", &[]));
    }
    for session in &view.sessions {
        session_lines(&mut out, &words, session);
    }
    // Self mode counts every candidate; SS mode counts only the programs it does not name.
    let counts = match mode {
        Mode::SelfCheck => window_line(&words, &view.counts),
        Mode::Ss => words.get(
            "game.ss_counts",
            &[("list", &window_line(&words, &view.unnamed))],
        ),
    };
    let _ = writeln!(out, "  {counts}");
    let installs = &view.unmatched_installs;
    for (window, count) in [
        ("before", installs.before),
        ("during", installs.during),
        ("after", installs.after),
    ] {
        if count > 0 {
            let note = words.get(
                "game.note.unmatched_installs",
                &[("count", &count.to_string())],
            );
            let _ = writeln!(
                out,
                "  {}: {note}",
                words.get(&format!("game.window.{window}"), &[])
            );
        }
    }
    // A clock change is stated with both times only when both were recorded; the caveat is said once
    // when the System log does not reach back far enough to show every change.
    for change in &view.clock.changes {
        let detail = match (&change.old_time, &change.new_time) {
            (Some(old), Some(new)) => words.get("game.clock.detail", &[("old", old), ("new", new)]),
            _ => String::new(),
        };
        let _ = writeln!(
            out,
            "  {}",
            words.get(
                "game.clock.changed",
                &[("at", &change.changed_at), ("detail", &detail)],
            )
        );
    }
    if view.clock.history == ClockHistory::NotKnown {
        let _ = writeln!(out, "  {}", words.get("game.clock.not_known", &[]));
    }
    let _ = writeln!(out, "  {}", words.get("game.order", &[]));
    let _ = writeln!(out, "  {}", words.get("game.windows_unmeasured", &[]));
    for candidate in &view.candidates {
        candidate_lines(&mut out, &words, candidate);
    }
    out
}

/// A session's header, its span, and its marker: the latest one also says whether its L1 fact holds.
fn session_lines(out: &mut String, words: &Words, session: &GameSession) {
    let edition = words.get(&format!("session.edition.{}", session.edition), &[]);
    let _ = writeln!(out, "  {} {edition}", words.get("session.session", &[]));
    match &session.end {
        Some(end) => {
            let _ = writeln!(out, "    {} – {end}", session.start);
        }
        None => {
            let _ = writeln!(out, "    {}", session.start);
        }
    }
    if session.latest {
        let _ = writeln!(out, "    {}", words.get("game.session.latest", &[]));
        let _ = writeln!(
            out,
            "    {}: {}",
            words.get("game.session.l1_label", &[]),
            session_l1(words, session)
        );
    } else {
        let _ = writeln!(
            out,
            "    {}",
            words.get("game.session.earlier", &[("at", &session.start)])
        );
    }
}

/// The L1 value of a session: its count when the records loaded files from outside, else the fact or
/// the reason it is not known.
fn session_l1(words: &Words, session: &GameSession) -> String {
    match (&session.l1, session.loaded_outside) {
        (IdentityFact::True, Some(count)) => {
            words.get("game.session.l1", &[("count", &count.to_string())])
        }
        (IdentityFact::True, None) => words.get("game.fact.l1", &[]),
        (IdentityFact::False, _) => words.get("game.fact.l1_false", &[]),
        (IdentityFact::NotKnown { reason }, _) => {
            words.get(&format!("game.nk.{}", identity_reason(reason)), &[])
        }
    }
}

/// The four window counts on one line, in the order of the view, joined by " · ".
fn window_line(words: &Words, counts: &WindowCounts) -> String {
    let windows = [
        ("before", counts.before),
        ("during", counts.during),
        ("after", counts.after),
        ("before_scan", counts.before_scan),
    ];
    let mut line = String::new();
    for (index, (window, count)) in windows.into_iter().enumerate() {
        if index > 0 {
            line.push_str(" · ");
        }
        let _ = write!(
            line,
            "{} {count}",
            words.get(&format!("game.window.{window}"), &[])
        );
    }
    line
}

/// A candidate's name and path, then one line per fact that is true or not known, then its notes.
/// A false fact and I5 (deferred) are not listed: a line for them would say nothing about the file.
fn candidate_lines(out: &mut String, words: &Words, candidate: &GameCandidate) {
    let _ = writeln!(out, "  {}", candidate.name);
    if let Some(path) = &candidate.path {
        let _ = writeln!(out, "    {path}");
    }
    let identities = [
        ("i1", &candidate.i1),
        ("i2", &candidate.i2),
        ("i3", &candidate.i3),
        ("i4", &candidate.i4),
        ("l1", &candidate.l1),
    ];
    for (id, fact) in identities {
        match fact {
            IdentityFact::True => {
                let _ = writeln!(
                    out,
                    "    ■ {}  ({})",
                    words.get(&format!("game.fact.{id}"), &[]),
                    words.get(&format!("game.cause.{id}"), &[])
                );
            }
            IdentityFact::False => {}
            IdentityFact::NotKnown { reason } => {
                let _ = writeln!(
                    out,
                    "    ? {}: {}",
                    words.get(&format!("game.fact.{id}"), &[]),
                    words.get(&format!("game.nk.{}", identity_reason(reason)), &[])
                );
            }
        }
    }
    let times = [
        ("t1", &candidate.t1),
        ("t2", &candidate.t2),
        ("t3", &candidate.t3),
        ("t4", &candidate.t4),
    ];
    for (id, fact) in times {
        if matches!(fact, TimeFact::True) {
            let _ = writeln!(
                out,
                "    · {}  ({})",
                words.get(&format!("game.fact.{id}"), &[]),
                words.get(&format!("game.cause.{id}"), &[])
            );
        }
    }
    // R is a count of sessions, so it is a fact only once a second session holds the same program.
    let near = candidate.near_sessions;
    if near.near >= 2 {
        let _ = writeln!(
            out,
            "    · {}  ({})",
            words.get(
                "game.fact.r",
                &[
                    ("near", &near.near.to_string()),
                    ("found", &near.found.to_string())
                ],
            ),
            words.get("game.cause.r", &[])
        );
    }
    for at in &candidate.installed_at {
        let _ = writeln!(
            out,
            "    {}",
            words.get("game.note.installed", &[("at", at)])
        );
    }
    if candidate.refused_by_code_integrity {
        let _ = writeln!(out, "    {}", words.get("game.note.code_integrity", &[]));
    }
}

/// The locale key's reason for a file identity fact that is not known (ADR 0079, ADR 0082).
fn identity_reason(reason: &IdentityNotKnownReason) -> &'static str {
    match reason {
        IdentityNotKnownReason::RecordedFilesNotRun => "recorded_files_not_run",
        IdentityNotKnownReason::NoObservationForPath => "no_observation_for_path",
        IdentityNotKnownReason::NotRead => "not_read",
        IdentityNotKnownReason::Unverifiable => "unverifiable",
        IdentityNotKnownReason::NoPath => "no_path",
        IdentityNotKnownReason::Deferred => "deferred",
        IdentityNotKnownReason::NotCounted => "not_counted",
        IdentityNotKnownReason::EarlierSession => "earlier_session",
    }
}

#[cfg(test)]
mod tests {
    use rongroi_core::model::Mode;
    use rongroi_core::view::{
        GameCandidate, GameSession, GameWindows, IdentityFact, IdentityNotKnownReason,
        NearSessions, TimeFact, WindowCounts,
    };

    use super::section;
    use crate::output::Lang;
    use crate::trace_ages::Words;

    const EN: &str = include_str!("../../../apps/desktop/src/locales/en/report.json");
    const TH: &str = include_str!("../../../apps/desktop/src/locales/th/report.json");

    /// A latest Legacy session from 20:00 to 21:00 on 22 October 2026, its L1 not counted.
    fn legacy_session() -> GameSession {
        GameSession {
            edition: "legacy".to_owned(),
            start: "2026-10-22T20:00:00Z".to_owned(),
            end: Some("2026-10-22T21:00:00Z".to_owned()),
            latest: true,
            l1: IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::NotCounted,
            },
            loaded_outside: None,
        }
    }

    /// A candidate with no true fact, at `path` when one is given.
    fn candidate(name: &str, path: Option<&str>) -> GameCandidate {
        GameCandidate {
            name: name.to_owned(),
            path: path.map(str::to_owned),
            t1: TimeFact::False,
            t2: TimeFact::False,
            t3: TimeFact::False,
            t4: TimeFact::False,
            i1: IdentityFact::False,
            i2: IdentityFact::False,
            i3: IdentityFact::False,
            i4: IdentityFact::False,
            i5: IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::Deferred,
            },
            l1: IdentityFact::NotKnown {
                reason: IdentityNotKnownReason::NotCounted,
            },
            near_sessions: NearSessions { near: 1, found: 1 },
            installed_at: Vec::new(),
            refused_by_code_integrity: false,
        }
    }

    /// One session, and one candidate whose file is gone (I1) and whose time is in the session (T2).
    fn view_with_one_candidate() -> GameWindows {
        let mut shown = candidate("payload.exe", Some("C:\\Tools\\payload.exe"));
        shown.i1 = IdentityFact::True;
        shown.t2 = TimeFact::True;
        GameWindows {
            sessions: vec![legacy_session()],
            candidates: vec![shown],
            counts: WindowCounts {
                before: 0,
                during: 1,
                after: 0,
                before_scan: 0,
            },
            ..GameWindows::default()
        }
    }

    /// One session with a clock change inside its span, both times held and the history known.
    fn view_with_a_clock_change() -> GameWindows {
        GameWindows {
            sessions: vec![legacy_session()],
            clock: serde_json::from_value(serde_json::json!({
                "changes": [{
                    "changed_at": "2026-10-22T20:30:00Z",
                    "old_time": "2026-10-22T20:29:00Z",
                    "new_time": "2026-10-22T20:31:00Z"
                }],
                "history": "known"
            }))
            .unwrap(),
            ..GameWindows::default()
        }
    }

    /// The four window counts as one line, in the order the view gives them, joined by " · ".
    fn window_line(
        words: &Words,
        before: usize,
        during: usize,
        after: usize,
        before_scan: usize,
    ) -> String {
        [
            ("before", before),
            ("during", during),
            ("after", after),
            ("before_scan", before_scan),
        ]
        .map(|(window, count)| {
            format!(
                "{} {count}",
                words.get(&format!("game.window.{window}"), &[])
            )
        })
        .join(" · ")
    }

    /// (c1) With no game-window view there is nothing to print, in either mode.
    #[test]
    fn no_view_prints_nothing() {
        assert!(section(None, Mode::SelfCheck, Lang::En).is_empty());
        assert!(section(None, Mode::Ss, Lang::Th).is_empty());
    }

    /// (c2) Self mode, English: the title with its experimental label, the candidate with its name,
    /// its path on the next line, its identity fact with the cause, its time fact, and the four counts.
    #[test]
    fn self_mode_names_the_candidate_its_facts_and_the_window_counts() {
        let text = section(Some(&view_with_one_candidate()), Mode::SelfCheck, Lang::En);
        let words = Words::new(Lang::En);
        assert!(
            text.contains("Programs recorded near a game session (experimental)"),
            "{text}"
        );
        assert!(
            text.contains(
                "■ its file is no longer at the recorded path  (a self-deleting installer, Storage Sense, a removed USB drive)"
            ),
            "{text}"
        );
        assert!(text.contains("· recorded during a session"), "{text}");
        assert!(text.contains("payload.exe"), "{text}");
        assert!(
            text.lines()
                .any(|line| line.starts_with(' ') && line.trim() == "C:\\Tools\\payload.exe"),
            "the path is not on its own indented line in\n{text}"
        );
        assert!(
            !words.get("game.window.during", &[]).is_empty(),
            "game.window.during has no English text"
        );
        let counts = window_line(&words, 0, 1, 0, 0);
        assert!(
            text.lines().any(|line| line.trim() == counts),
            "missing the window counts line {counts:?} in\n{text}"
        );
    }

    /// (c3) Thai: the same section under its Thai title.
    #[test]
    fn thai_names_the_section_in_thai() {
        let text = section(Some(&view_with_one_candidate()), Mode::SelfCheck, Lang::Th);
        assert!(
            text.contains("โปรแกรมที่ถูกบันทึกไว้ใกล้ช่วงเล่นเกม (ทดลอง)"),
            "{text}"
        );
    }

    /// (c4) SS mode: the rule is stated in English, the unnamed programs are counted under their own
    /// label, and the Self window line with every count is not printed.
    #[test]
    fn ss_mode_states_the_rule_and_counts_the_unnamed_without_the_self_window_line() {
        let mut view = view_with_one_candidate();
        view.counts = WindowCounts {
            before: 0,
            during: 2,
            after: 0,
            before_scan: 0,
        };
        let text = section(Some(&view), Mode::Ss, Lang::En);
        let words = Words::new(Lang::En);
        let rule = words.get("game.ss_rule", &[]);
        assert!(!rule.is_empty(), "game.ss_rule has no English text");
        assert!(text.contains(&rule), "{text}");
        assert!(text.contains("Other programs, not named:"), "{text}");
        let self_line = window_line(&words, 0, 2, 0, 0);
        assert!(
            !text.lines().any(|line| line.trim() == self_line),
            "the Self window line {self_line:?} is in SS mode's\n{text}"
        );
    }

    /// (c5) A clock change with both times is stated with them, and the caveat follows it.
    #[test]
    fn a_clock_change_with_both_times_is_stated_with_them() {
        let text = section(Some(&view_with_a_clock_change()), Mode::SelfCheck, Lang::En);
        assert!(
            text.contains(
                "The clock was changed at 2026-10-22T20:30:00Z (from 2026-10-22T20:29:00Z to 2026-10-22T20:31:00Z); times before and after may not be on the same clock."
            ),
            "{text}"
        );
    }

    /// Self mode, English: the not-yet-measured line is printed right after the order line, so the
    /// reader meets the caveat before the candidates.
    #[test]
    fn the_windows_unmeasured_line_follows_the_order_line() {
        let text = section(Some(&view_with_one_candidate()), Mode::SelfCheck, Lang::En);
        let unmeasured =
            "The 30-minute windows have not yet been measured on many ordinary gaming PCs.";
        let order_at = text
            .lines()
            .position(|line| line.contains("Ordered by how many facts about the file hold"));
        let unmeasured_at = text.lines().position(|line| line.trim() == unmeasured);
        assert!(order_at.is_some(), "no order line in\n{text}");
        assert!(unmeasured_at.is_some(), "no unmeasured line in\n{text}");
        assert!(
            unmeasured_at > order_at,
            "the unmeasured line comes before the order line in\n{text}"
        );
    }

    /// The text at the dotted `key` in a locale file, or `None`. Read from the file itself, not through
    /// `Words`, which falls back to English and would hide a key missing from Thai.
    fn own_text(locale: &str, key: &str) -> Option<String> {
        let root: serde_json::Value = serde_json::from_str(locale).ok()?;
        key.split('.')
            .try_fold(&root, |node, part| node.get(part))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }

    /// (c6) Every `game.*` key this module uses, and the session keys it shares with the trace ages, is
    /// a non-empty string in both locale files.
    #[test]
    fn every_key_this_section_uses_is_in_both_languages() {
        let mut keys: Vec<String> = [
            "game.title",
            "game.experimental",
            "game.intro",
            "game.ss_rule",
            "game.session.latest",
            "game.session.earlier",
            "game.session.l1_label",
            "game.session.l1",
            "game.fact.l1_false",
            "game.fact.i1",
            "game.fact.i2",
            "game.fact.i3",
            "game.fact.i4",
            "game.fact.l1",
            "game.fact.t1",
            "game.fact.t2",
            "game.fact.t3",
            "game.fact.t4",
            "game.fact.r",
            "game.cause.i1",
            "game.cause.i2",
            "game.cause.i3",
            "game.cause.i4",
            "game.cause.l1",
            "game.cause.t1",
            "game.cause.t2",
            "game.cause.t3",
            "game.cause.t4",
            "game.cause.r",
            "game.window.before",
            "game.window.during",
            "game.window.after",
            "game.window.before_scan",
            "game.ss_counts",
            "game.note.unmatched_installs",
            "game.note.installed",
            "game.note.code_integrity",
            "game.clock.changed",
            "game.clock.detail",
            "game.clock.not_known",
            "game.order",
            "game.windows_unmeasured",
            "session.session",
            "session.edition.legacy",
            "session.edition.enhanced",
        ]
        .map(str::to_owned)
        .to_vec();
        // The reasons a candidate's or a session's identity fact can be not known for, as the view
        // names them (ADR 0078 section 5, ADR 0079, ADR 0082 section 5).
        for reason in [
            "recorded_files_not_run",
            "no_observation_for_path",
            "not_read",
            "unverifiable",
            "no_path",
            "deferred",
            "not_counted",
            "earlier_session",
        ] {
            keys.push(format!("game.nk.{reason}"));
        }
        for (lang, locale) in [(Lang::En, EN), (Lang::Th, TH)] {
            for key in &keys {
                assert!(
                    own_text(locale, key).is_some_and(|text| !text.is_empty()),
                    "{lang:?}: {key}"
                );
            }
        }
    }
}
