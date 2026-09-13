// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a Self or SS view may show. Privacy is decided here, not in the UI (AGENTS.md hard rule 5).

use serde::{Deserialize, Serialize};

use crate::model::{
    Evidence, EvidenceState, Mode, OwnTraceEntry, Report, ReportHeader, Strength, UnmatchedGroup,
    UnmeasuredReason,
};

/// Replacement for the user-profile part of a path in SS mode.
pub const USERPROFILE_PLACEHOLDER: &str = "%USERPROFILE%";

/// Counts of evidence an SS view does not list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenCounts {
    /// Rules that looked and found nothing.
    pub not_found: usize,
    /// Rules that could not look for a reason the rule itself named in `unmeasured_when`.
    ///
    /// Split from the unexpected ones because one integer mixing "this version of Windows keeps no
    /// such record" with "the folder would not open" says nothing a reader can use (ADR 0027).
    pub unmeasured_expected: usize,
    /// Rules that could not look for a reason the rule did not name. SS mode lists such a result,
    /// so the only ones counted here are the `not_admin` results the scope statement carries.
    pub unmeasured_unexpected: usize,
    /// Unmatched observations. SS mode counts them instead of listing them (ADR 0014).
    pub unmatched: usize,
}

/// Facts about the scan as a whole, stated once above the evidence rather than on every rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeNotes {
    /// How many rules were unmeasured because the scan did not have administrator rights.
    ///
    /// It is one fact about the scan and it applies to every rule at once, so repeating it per rule
    /// would show a reviewer N red-looking lines that all say the same thing. It is also the one
    /// unmeasured reason with a remedy: it is what makes the restart-as-administrator offer worth
    /// taking (ADR 0012, ADR 0027).
    ///
    /// This is not a hidden count and must not be added to them: in SS mode the same rules are
    /// counted in [`HiddenCounts::unmeasured_expected`] or [`HiddenCounts::unmeasured_unexpected`],
    /// which together account for every unlisted result. Self mode lists all of them and carries
    /// this number as well.
    pub not_admin: usize,
    /// How many rules were unmeasured because the collector never looked at their source.
    ///
    /// The same shape as [`Self::not_admin`] and here for the same reason: a source this program
    /// stopped short of is one fact about how far the scan got, not N facts about the PC. Additive
    /// to the view, and [`crate::model::REPORT_SCHEMA_VERSION`] stays at 1 (ADR 0030).
    #[serde(default)]
    pub not_attempted: usize,
}

/// A report as one audience may see it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportView {
    /// Audience.
    pub mode: Mode,
    /// Facts about the scan.
    pub header: ReportHeader,
    /// Evidence this view shows.
    pub evidence: Vec<Evidence>,
    /// What this program itself left in what the collectors saw. Shown in both modes: hiding "this
    /// was us" from the person watching a screenshare would be less transparent, not more (ADR 0010).
    pub own_traces: Vec<OwnTraceEntry>,
    /// What the collectors saw that no rule matched. Self mode lists it; SS mode leaves it empty
    /// and counts it in `hidden.unmatched` (ADR 0014).
    pub unmatched: Vec<UnmatchedGroup>,
    /// Facts about the scan itself, above the evidence in both modes.
    #[serde(default)]
    pub scope: ScopeNotes,
    /// What this view does not list.
    pub hidden: HiddenCounts,
}

/// The reasons a view states once above the evidence instead of as a row per rule (ADR 0027,
/// ADR 0030).
fn scope_notes(report: &Report) -> ScopeNotes {
    let counted = |wanted: UnmeasuredReason| {
        report
            .evidence
            .iter()
            .filter(|item| matches!(item.state, EvidenceState::Unmeasured { reason, .. } if reason == wanted))
            .count()
    };
    ScopeNotes {
        not_admin: counted(UnmeasuredReason::NotAdmin),
        not_attempted: counted(UnmeasuredReason::NotAttempted),
    }
}

/// Whether an SS view lists this piece of evidence, rather than only counting it.
///
/// A match is always listed. A posture rule that looked is listed whatever it found, because the
/// machine's posture is the thing an SS reviewer came for (ADR 0011). An unmeasured result is listed
/// only when its reason is one the rule did not name in `unmeasured_when`: a reason the author
/// declared is one they said happens on ordinary machines, and a row per such rule is the "sea of
/// red flags" that teaches a reviewer to stop reading (ADR 0027).
///
/// Two exceptions in each direction, both from [`UnmeasuredReason`] and both about who the fact
/// belongs to (ADR 0030):
///
/// - `not_admin` and `not_attempted` are never a row. Each is one fact about the **scan** that
///   applies to every rule it stopped, and each is stated once in [`ScopeNotes`].
/// - `partial`, `budget_spent` and `read_failed` are always a row, declared or not. Each says the
///   artifact was reachable and that the read of it did not finish, which is not something a rule
///   author could have anticipated about the machine and so is not theirs to declare away
///   (ADR 0030, ADR 0032).
fn ss_lists(item: &Evidence) -> bool {
    match &item.state {
        EvidenceState::Found { .. } => true,
        EvidenceState::NotFound { .. } => item.strength == Strength::Posture,
        EvidenceState::Unmeasured { reason, .. } if reason.is_scope_statement() => false,
        EvidenceState::Unmeasured { reason, .. } if reason.is_always_listed() => true,
        EvidenceState::Unmeasured { expected, .. } => !expected,
    }
}

/// Builds the view for `mode`.
///
/// - Self: everything, unchanged.
/// - SS: what [`ss_lists`] admits, with user names in paths replaced by
///   [`USERPROFILE_PLACEHOLDER`]; every other piece of evidence is counted in [`HiddenCounts`];
///   unmatched observations are counted and none are listed (ADR 0014).
///
/// Both modes carry the same [`ScopeNotes`]: they are facts about the scan, and SS mode's filter is
/// about evidence.
pub fn for_mode(report: &Report, mode: Mode) -> ReportView {
    match mode {
        Mode::SelfCheck => ReportView {
            mode,
            header: report.header.clone(),
            evidence: report.evidence.clone(),
            own_traces: report.own_traces.clone(),
            unmatched: report.unmatched.clone(),
            scope: scope_notes(report),
            hidden: HiddenCounts::default(),
        },
        Mode::Ss => {
            let mut hidden = HiddenCounts::default();
            let mut evidence = Vec::new();
            for item in &report.evidence {
                if ss_lists(item) {
                    evidence.push(redacted(item));
                    continue;
                }
                match &item.state {
                    EvidenceState::NotFound { .. } => hidden.not_found += 1,
                    EvidenceState::Unmeasured { expected: true, .. } => {
                        hidden.unmeasured_expected += 1;
                    }
                    EvidenceState::Unmeasured { .. } => hidden.unmeasured_unexpected += 1,
                    // `ss_lists` admits every match, so nothing reaches here.
                    EvidenceState::Found { .. } => {}
                }
            }
            // Counted, never listed. SS mode promises the person being screenshared that only what
            // matches a rule is shown; a raw listing of every file and process name a collector saw
            // would break that promise, and no redaction pass makes such a listing safe (ADR 0014).
            hidden.unmatched = report
                .unmatched
                .iter()
                .map(|group| group.observations.len())
                .sum();
            ReportView {
                mode,
                header: report.header.clone(),
                evidence,
                own_traces: report.own_traces.iter().map(redacted_own_trace).collect(),
                unmatched: Vec::new(),
                scope: scope_notes(report),
                hidden,
            }
        }
    }
}

fn redacted(item: &Evidence) -> Evidence {
    let mut item = item.clone();
    if let EvidenceState::Found { observations } = &mut item.state {
        for observation in observations {
            observation.fields.values_mut().for_each(redact_value);
        }
    }
    item
}

/// An own trace as SS mode shows it. It is always listed — the mode's "matches and posture only"
/// filter is about evidence, and this is not evidence — but its paths are of the same shape as any
/// other and carry the same user name, so they go through the same redaction (ADR 0010).
fn redacted_own_trace(entry: &OwnTraceEntry) -> OwnTraceEntry {
    let mut entry = entry.clone();
    entry.observation.fields.values_mut().for_each(redact_value);
    entry
}

fn redact_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = redact_user_paths(text),
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact_value),
        serde_json::Value::Object(map) => map.values_mut().for_each(redact_value),
        _ => {}
    }
}

/// Replaces `X:\Users\<name>` (either slash, any case) with [`USERPROFILE_PLACEHOLDER`].
pub fn redact_user_paths(input: &str) -> String {
    const SEGMENT: &[u8] = b"users";
    let lower = input.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut copied_to = 0;
    let mut i = 1;
    // `X:\users\` is 9 bytes starting at the drive letter; `i` points at the colon.
    while i + 2 + SEGMENT.len() < bytes.len() {
        let separator = bytes[i + 1];
        let is_profile_root = bytes[i] == b':'
            && bytes[i - 1].is_ascii_alphabetic()
            && (separator == b'\\' || separator == b'/')
            && &bytes[i + 2..i + 2 + SEGMENT.len()] == SEGMENT
            && bytes[i + 2 + SEGMENT.len()] == separator;
        if is_profile_root {
            let name_start = i + 3 + SEGMENT.len();
            let name_end = input[name_start..]
                .find(['\\', '/'])
                .map_or(input.len(), |offset| name_start + offset);
            if name_end > name_start {
                out.push_str(&input[copied_to..i - 1]);
                out.push_str(USERPROFILE_PLACEHOLDER);
                copied_to = name_end;
                i = name_end + 1;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&input[copied_to..]);
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::bundle::BundleInfo;
    use crate::model::{Observation, UnmatchedGroup, UnmeasuredReason};
    use crate::provenance::Provenance;

    const USER: &str = "fixtureuser";

    #[test]
    fn redacts_backslash_and_forward_slash_paths() {
        assert_eq!(
            redact_user_paths(r"C:\Users\fixtureuser\AppData\Local\FiveM\x.dll"),
            r"%USERPROFILE%\AppData\Local\FiveM\x.dll"
        );
        assert_eq!(
            redact_user_paths("d:/users/สมชาย/Desktop/a.exe"),
            "%USERPROFILE%/Desktop/a.exe"
        );
    }

    #[test]
    fn redacts_every_occurrence_and_leaves_other_text() {
        let input = r"from C:\USERS\a\x to C:\Users\b\y (D:\Games\users\z)";
        assert_eq!(
            redact_user_paths(input),
            r"from %USERPROFILE%\x to %USERPROFILE%\y (D:\Games\users\z)"
        );
    }

    #[test]
    fn profile_root_without_name_is_unchanged() {
        assert_eq!(redact_user_paths(r"C:\Users\"), r"C:\Users\");
        assert_eq!(redact_user_paths("no paths here"), "no paths here");
    }

    fn header() -> ReportHeader {
        ReportHeader {
            schema_version: 1,
            provenance: Provenance::from_parts(None, "0.0.0-test", None, None),
            rules_bundle: BundleInfo {
                schema_version: 1,
                sha256: "0".repeat(64),
                rule_count: 3,
            },
            platform: "windows".to_owned(),
            os_build: None,
            elevated: Some(false),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    /// One piece of evidence of each shape the two modes treat differently.
    fn evidence() -> Vec<Evidence> {
        let found = Evidence {
            rule_id: "found".to_owned(),
            collector: "fivem_dir".to_owned(),
            strength: Strength::Presence,
            state: EvidenceState::Found {
                observations: vec![Observation {
                    collector: "fivem_dir".to_owned(),
                    fields: BTreeMap::from([(
                        "path".to_owned(),
                        serde_json::Value::from(format!(
                            r"C:\Users\{USER}\AppData\Local\FiveM\FiveM.app\plugins\x.dll"
                        )),
                    )]),
                }],
            },
        };
        let not_found = Evidence {
            rule_id: "not-found".to_owned(),
            collector: "fivem_dir".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::NotFound {
                retention: "7 days".to_owned(),
            },
        };
        // A posture rule that said in `unmeasured_when` that this reason happens on some machines.
        let expected_unmeasured = Evidence {
            rule_id: "posture".to_owned(),
            collector: "posture".to_owned(),
            strength: Strength::Posture,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                expected: true,
            },
        };
        // A reason its rule did not name: something the author did not anticipate stopped the read.
        let unexpected_unmeasured = Evidence {
            rule_id: "unexpected".to_owned(),
            collector: "prefetch".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::ReadFailed,
                expected: false,
            },
        };
        // A fact about the scan rather than about the machine, whatever the rule declared.
        let not_admin = Evidence {
            rule_id: "not-admin".to_owned(),
            collector: "prefetch".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::NotAdmin,
                expected: false,
            },
        };
        // A source this program stopped short of: one fact about how far the scan got, like
        // `not_admin`, and never a row of its own (ADR 0030).
        let not_attempted = Evidence {
            rule_id: "not-attempted".to_owned(),
            collector: "evtx".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::NotAttempted,
                expected: true,
            },
        };
        // Declared by its rule and listed anyway: "part of this was read" is a fact about what this
        // program did, not one the author could have anticipated about the machine (ADR 0030).
        let partial = Evidence {
            rule_id: "partial".to_owned(),
            collector: "prefetch".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::Partial,
                expected: true,
            },
        };
        vec![
            found,
            not_found,
            expected_unmeasured,
            unexpected_unmeasured,
            not_admin,
            not_attempted,
            partial,
        ]
    }

    fn report() -> Report {
        Report {
            header: header(),
            evidence: evidence(),
            own_traces: vec![OwnTraceEntry {
                collector: "process".to_owned(),
                observation: Observation {
                    collector: "process".to_owned(),
                    fields: BTreeMap::from([
                        (
                            "name".to_owned(),
                            serde_json::Value::from("aeterna-rongroi.exe"),
                        ),
                        (
                            "path".to_owned(),
                            serde_json::Value::from(format!(
                                r"C:\Users\{USER}\Downloads\aeterna-rongroi.exe"
                            )),
                        ),
                    ]),
                },
            }],
            // What `fivem_dir` saw: it ships with no rule, so nothing about this file matched one.
            unmatched: vec![UnmatchedGroup {
                collector: "fivem_dir".to_owned(),
                observations: vec![Observation {
                    collector: "fivem_dir".to_owned(),
                    fields: BTreeMap::from([(
                        "path".to_owned(),
                        serde_json::Value::from(format!(
                            r"C:\Users\{USER}\AppData\Local\FiveM\FiveM.app\plugins\overlay.dll"
                        )),
                    )]),
                }],
            }],
        }
    }

    #[test]
    fn self_view_shows_everything_unchanged() {
        let report = report();
        let view = for_mode(&report, Mode::SelfCheck);
        assert_eq!(view.evidence, report.evidence);
        assert_eq!(view.hidden, HiddenCounts::default());
    }

    #[test]
    fn ss_view_shows_found_and_posture_and_counts_the_rest() {
        let view = for_mode(&report(), Mode::Ss);
        let ids: Vec<&str> = view.evidence.iter().map(|e| e.rule_id.as_str()).collect();
        assert_eq!(ids, ["found", "unexpected", "partial"]);
        assert_eq!(
            view.hidden,
            HiddenCounts {
                not_found: 1,
                unmeasured_expected: 2,
                unmeasured_unexpected: 1,
                unmatched: 1
            }
        );
    }

    /// The whole of what `unmeasured_when` does to a view: a reason the rule named is a number, and
    /// a reason it did not name is a line, because that one says something nobody anticipated
    /// stopped the measurement (ADR 0027).
    #[test]
    fn ss_view_lists_an_unexpected_unmeasured_result_and_counts_an_expected_one() {
        let view = for_mode(&report(), Mode::Ss);
        let ids: Vec<&str> = view.evidence.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(ids.contains(&"unexpected"), "{ids:?}");
        assert!(!ids.contains(&"posture"), "{ids:?}");
        assert_eq!(view.hidden.unmeasured_expected, 2);
    }

    /// Self mode lists both, as it lists everything else.
    #[test]
    fn self_view_lists_both_the_expected_and_the_unexpected_unmeasured_result() {
        let view = for_mode(&report(), Mode::SelfCheck);
        let ids: Vec<&str> = view.evidence.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(ids.contains(&"unexpected"), "{ids:?}");
        assert!(ids.contains(&"posture"), "{ids:?}");
        assert_eq!(view.hidden, HiddenCounts::default());
    }

    /// A posture rule is listed in SS mode whatever its state — except when it could not look for a
    /// reason it had itself declared, which is a number about the scan and not a row about the PC.
    #[test]
    fn ss_view_does_not_list_a_posture_rule_that_expected_to_be_unmeasured() {
        let view = for_mode(&report(), Mode::Ss);
        assert!(
            !view.evidence.iter().any(|e| e.rule_id == "posture"),
            "{:?}",
            view.evidence
        );
    }

    /// Missing administrator rights is one fact about the scan that applies to every rule at once,
    /// and the one unmeasured reason with a remedy, so it is stated once above the evidence and
    /// never as a row of its own in SS mode (ADR 0012, ADR 0027).
    #[test]
    fn not_admin_is_a_scope_statement_in_both_modes_and_never_an_ss_row() {
        let report = report();
        assert_eq!(for_mode(&report, Mode::SelfCheck).scope.not_admin, 1);
        let ss = for_mode(&report, Mode::Ss);
        assert_eq!(ss.scope.not_admin, 1);
        assert!(
            !ss.evidence.iter().any(|e| e.rule_id == "not-admin"),
            "{:?}",
            ss.evidence
        );
        // Still accounted for: the hidden counts cover every result the view does not list.
        assert_eq!(ss.hidden.unmeasured_unexpected, 1);
    }

    /// Self mode passes unmatched observations through whole. For a collector that ships without a
    /// rule they are the only place what it saw can be read at all (ADR 0014).
    #[test]
    fn self_view_shows_unmatched_observations() {
        let report = report();
        assert_eq!(
            for_mode(&report, Mode::SelfCheck).unmatched,
            report.unmatched
        );
    }

    /// SS mode's promise is "only what matches a rule, paths redacted". A raw listing of every file
    /// and process name a collector saw would break that promise whatever the redaction, so SS mode
    /// counts unmatched observations and lists none of them (ADR 0014).
    #[test]
    fn ss_view_lists_no_unmatched_observations_and_counts_them() {
        let view = for_mode(&report(), Mode::Ss);
        assert!(view.unmatched.is_empty(), "{:?}", view.unmatched);
        assert_eq!(view.hidden.unmatched, 1);
    }

    /// Own traces are transparency about the tool, not evidence about the machine, so SS mode's
    /// "only matches and posture" filter does not apply to them: hiding "this was us" from the
    /// person watching the screenshare would be less transparent, not more (ADR 0010).
    #[test]
    fn both_views_show_own_traces() {
        let report = report();
        assert_eq!(
            for_mode(&report, Mode::SelfCheck).own_traces,
            report.own_traces
        );
        assert_eq!(for_mode(&report, Mode::Ss).own_traces.len(), 1);
    }

    #[test]
    fn ss_view_redacts_the_path_of_an_own_trace() {
        let view = for_mode(&report(), Mode::Ss);
        let path = view.own_traces[0]
            .observation
            .fields
            .get("path")
            .and_then(serde_json::Value::as_str);
        assert_eq!(path, Some(r"%USERPROFILE%\Downloads\aeterna-rongroi.exe"));
        // The name is not a path and is not touched; PRIVACY.md says so (ADR 0010).
        assert_eq!(
            view.own_traces[0]
                .observation
                .fields
                .get("name")
                .and_then(serde_json::Value::as_str),
            Some("aeterna-rongroi.exe")
        );
    }

    /// The reasons a rule author cannot declare away. Each says the artifact was reachable and that
    /// the read of it did not finish, which is a fact about the scan and not one about the machine,
    /// so SS mode lists them even though the rule named them (ADR 0030).
    #[test]
    fn ss_view_lists_a_partial_result_even_though_its_rule_declared_it() {
        let view = for_mode(&report(), Mode::Ss);
        let ids: Vec<&str> = view.evidence.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(ids.contains(&"partial"), "{ids:?}");
    }

    /// The case ADR 0032 added, from the far side of the gate that now refuses the declaration:
    /// `expected: true` on a `read_failed` result is what an old bundle, or a rule set this build
    /// did not check, still hands the view. It is listed regardless — the guarantee belongs here and
    /// not only in `check-rules`.
    #[test]
    fn ss_view_lists_a_read_failed_result_even_though_its_rule_declared_it() {
        let mut report = report();
        report.evidence = vec![Evidence {
            rule_id: "read-failed".to_owned(),
            collector: "posture".to_owned(),
            strength: Strength::Posture,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::ReadFailed,
                expected: true,
            },
        }];

        let view = for_mode(&report, Mode::Ss);

        let ids: Vec<&str> = view.evidence.iter().map(|e| e.rule_id.as_str()).collect();
        assert_eq!(ids, ["read-failed"]);
        // Listed, so it is not also counted: every result is in exactly one of the two places. The
        // report's unmatched observations are untouched by this and are counted as they always are.
        assert_eq!(view.hidden.unmeasured_expected, 0);
        assert_eq!(view.hidden.unmeasured_unexpected, 0);
    }

    /// A source the collector never looked at is the same shape as missing administrator rights:
    /// one fact about how far the scan got, stated once above the evidence in both modes and never
    /// as a row of its own (ADR 0030).
    #[test]
    fn not_attempted_is_a_scope_statement_in_both_modes_and_never_an_ss_row() {
        let report = report();
        assert_eq!(for_mode(&report, Mode::SelfCheck).scope.not_attempted, 1);
        let ss = for_mode(&report, Mode::Ss);
        assert_eq!(ss.scope.not_attempted, 1);
        assert!(
            !ss.evidence.iter().any(|e| e.rule_id == "not-attempted"),
            "{:?}",
            ss.evidence
        );
        // Still accounted for: it was declared, so it is one of the expected ones.
        assert_eq!(ss.hidden.unmeasured_expected, 2);
    }

    /// The two questions [`UnmeasuredReason`] answers for a view, asserted on every reason at once
    /// so that one added later cannot quietly default to "ordinary row".
    #[test]
    fn every_reason_says_whether_it_is_a_scope_statement_or_always_listed() {
        use UnmeasuredReason as R;
        for reason in [
            R::NotWindows,
            R::NotOnThisOs,
            R::NotAdmin,
            R::NotAttempted,
            R::AccessDenied,
            R::ServiceDisabled,
            R::SourceAbsent,
            R::SourceEmpty,
            R::Partial,
            R::BudgetSpent,
            R::ReadFailed,
            R::CollectorUnavailable,
        ] {
            let scope = reason.is_scope_statement();
            let listed = reason.is_always_listed();
            assert!(
                !(scope && listed),
                "{} is both a scope statement and always listed",
                reason.as_str()
            );
            assert_eq!(
                scope,
                matches!(reason, R::NotAdmin | R::NotAttempted),
                "{}",
                reason.as_str()
            );
            assert_eq!(
                listed,
                matches!(reason, R::Partial | R::BudgetSpent | R::ReadFailed),
                "{}",
                reason.as_str()
            );
        }
    }

    #[test]
    fn ss_view_never_contains_the_user_name() {
        let json = serde_json::to_string(&for_mode(&report(), Mode::Ss)).unwrap();
        assert!(!json.contains(USER), "{json}");
        assert!(json.contains("%USERPROFILE%"));
    }
}
