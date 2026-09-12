// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a Self or SS view may show. Privacy is decided here, not in the UI (AGENTS.md hard rule 5).

use serde::{Deserialize, Serialize};

use crate::model::{
    Evidence, EvidenceState, Mode, OwnTraceEntry, Report, ReportHeader, Strength, UnmatchedGroup,
};

/// Replacement for the user-profile part of a path in SS mode.
pub const USERPROFILE_PLACEHOLDER: &str = "%USERPROFILE%";

/// Counts of evidence an SS view does not list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenCounts {
    /// Rules that looked and found nothing.
    pub not_found: usize,
    /// Rules that could not look.
    pub unmeasured: usize,
    /// Unmatched observations. SS mode counts them instead of listing them (ADR 0014).
    pub unmatched: usize,
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
    /// What this view does not list.
    pub hidden: HiddenCounts,
}

/// Builds the view for `mode`.
///
/// - Self: everything, unchanged.
/// - SS: `Found` evidence and all posture evidence; other evidence is only counted; user names in
///   paths are replaced with [`USERPROFILE_PLACEHOLDER`]; unmatched observations are counted and
///   none are listed (ADR 0014).
pub fn for_mode(report: &Report, mode: Mode) -> ReportView {
    match mode {
        Mode::SelfCheck => ReportView {
            mode,
            header: report.header.clone(),
            evidence: report.evidence.clone(),
            own_traces: report.own_traces.clone(),
            unmatched: report.unmatched.clone(),
            hidden: HiddenCounts::default(),
        },
        Mode::Ss => {
            let mut hidden = HiddenCounts::default();
            let mut evidence = Vec::new();
            for item in &report.evidence {
                let shown = matches!(item.state, EvidenceState::Found { .. })
                    || item.strength == Strength::Posture;
                if shown {
                    evidence.push(redacted(item));
                } else if matches!(item.state, EvidenceState::NotFound { .. }) {
                    hidden.not_found += 1;
                } else {
                    hidden.unmeasured += 1;
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

    fn report() -> Report {
        let header = ReportHeader {
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
        };
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
        let posture_unmeasured = Evidence {
            rule_id: "posture".to_owned(),
            collector: "posture".to_owned(),
            strength: Strength::Posture,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
            },
        };
        let other_unmeasured = Evidence {
            rule_id: "unmeasured".to_owned(),
            collector: "prefetch".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::NotAdmin,
            },
        };
        Report {
            header,
            evidence: vec![found, not_found, posture_unmeasured, other_unmeasured],
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
        assert_eq!(ids, ["found", "posture"]);
        assert_eq!(
            view.hidden,
            HiddenCounts {
                not_found: 1,
                unmeasured: 1,
                unmatched: 1
            }
        );
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

    #[test]
    fn ss_view_never_contains_the_user_name() {
        let json = serde_json::to_string(&for_mode(&report(), Mode::Ss)).unwrap();
        assert!(!json.contains(USER), "{json}");
        assert!(json.contains("%USERPROFILE%"));
    }
}
