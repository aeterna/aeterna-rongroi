// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Turns collector runs and rules into evidence. Pure: no I/O, no clock, no platform checks.

use crate::bundle::Bundle;
use crate::model::{
    CollectorRun, Evidence, EvidenceState, Observation, OwnTraceEntry, Report, ReportHeader,
    UnmeasuredReason,
};
use crate::rules::{Rule, Status};

/// What the running program is, so that its own traces can be told apart from evidence about the
/// machine (ADR 0010).
///
/// Each binary's `main` computes it and passes it in. Nothing here reads it from the running
/// process: identity read ambiently could not be exercised from a fixture, and the behaviour would
/// then be testable only in a unit test of this module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelfIdentity {
    /// Full path of the running executable, when it is known.
    pub exe_path: Option<String>,
    /// SHA-256 of the running executable, lowercase hex, when it could be read.
    pub exe_sha256: Option<String>,
}

impl SelfIdentity {
    /// Whether `observation` is about this program rather than about the machine.
    ///
    /// Either it names the path this executable runs from, or it carries this executable's digest —
    /// which still identifies a copy that was renamed. Both are compared without regard to ASCII
    /// case, as Windows compares paths and as a rule's `allow` compares `sha256`.
    fn describes(&self, observation: &Observation) -> bool {
        let field = |name: &str| {
            observation
                .fields
                .get(name)
                .and_then(serde_json::Value::as_str)
        };
        let same_path = self
            .exe_path
            .as_deref()
            .zip(field("path"))
            .is_some_and(|(ours, seen)| ours.eq_ignore_ascii_case(seen));
        let same_hash = self
            .exe_sha256
            .as_deref()
            .zip(field("sha256"))
            .is_some_and(|(ours, seen)| ours.eq_ignore_ascii_case(seen));
        same_path || same_hash
    }
}

/// Evaluates every non-deprecated rule in `bundle` against `runs`.
pub fn evaluate(
    bundle: &Bundle,
    runs: &[CollectorRun],
    header: ReportHeader,
    self_identity: &SelfIdentity,
) -> Report {
    let (runs, own_traces) = partition_own_traces(runs, self_identity);
    let evidence = bundle
        .rules()
        .iter()
        .map(|sourced| &sourced.rule)
        .filter(|rule| rule.status != Status::Deprecated)
        .map(|rule| evaluate_rule(rule, &runs))
        .collect();
    Report {
        header,
        evidence,
        own_traces,
    }
}

/// Moves the observations that describe this program out of the runs and into their own bucket.
///
/// A run keeps its shape. Taking its last observation leaves `Measured` with none, which a rule
/// reads as `NotFound` — the collector did look, and saw nothing that was not us. Dropping the run,
/// or turning it into `Unmeasured`, would claim it could not look (ADR 0010). An `Unmeasured` run
/// carries no observations and passes through untouched.
fn partition_own_traces(
    runs: &[CollectorRun],
    self_identity: &SelfIdentity,
) -> (Vec<CollectorRun>, Vec<OwnTraceEntry>) {
    let mut kept = Vec::with_capacity(runs.len());
    let mut own_traces = Vec::new();
    for run in runs {
        let CollectorRun::Measured {
            collector,
            observations,
            gaps,
        } = run
        else {
            kept.push(run.clone());
            continue;
        };
        let mut remaining = Vec::with_capacity(observations.len());
        for observation in observations {
            if self_identity.describes(observation) {
                own_traces.push(OwnTraceEntry {
                    collector: collector.clone(),
                    observation: observation.clone(),
                });
            } else {
                remaining.push(observation.clone());
            }
        }
        kept.push(CollectorRun::Measured {
            collector: collector.clone(),
            observations: remaining,
            gaps: gaps.clone(),
        });
    }
    (kept, own_traces)
}

/// Evaluates one rule. Used by [`evaluate`] and by fixture checks in `cargo xtask check-rules`.
pub fn evaluate_rule(rule: &Rule, runs: &[CollectorRun]) -> Evidence {
    let state = match runs.iter().find(|run| run.collector() == rule.collector) {
        None => EvidenceState::Unmeasured {
            reason: UnmeasuredReason::CollectorUnavailable,
        },
        Some(CollectorRun::Unmeasured { reason, .. }) => {
            EvidenceState::Unmeasured { reason: *reason }
        }
        Some(CollectorRun::Measured {
            observations, gaps, ..
        }) => {
            let matched: Vec<Observation> = observations
                .iter()
                .filter(|observation| matches(rule, observation))
                .cloned()
                .collect();
            if !matched.is_empty() {
                EvidenceState::Found {
                    observations: matched,
                }
            } else if let Some(reason) = rule.matcher.keys().find_map(|field| gaps.get(field)) {
                // Nothing matched, but a field the rule needs was never read: "not found" would lie.
                EvidenceState::Unmeasured { reason: *reason }
            } else {
                EvidenceState::NotFound {
                    retention: rule.retention.clone(),
                }
            }
        }
    };
    Evidence {
        rule_id: rule.id.clone(),
        collector: rule.collector.clone(),
        strength: rule.strength,
        state,
    }
}

fn matches(rule: &Rule, observation: &Observation) -> bool {
    observation.collector == rule.collector
        && rule
            .matcher
            .iter()
            .all(|(field, expected)| observation.fields.get(field) == Some(expected))
        && !is_allowed(rule, observation)
}

fn is_allowed(rule: &Rule, observation: &Observation) -> bool {
    let field = |name: &str| {
        observation
            .fields
            .get(name)
            .and_then(serde_json::Value::as_str)
    };
    rule.allow.iter().any(|allow| {
        let by_hash = allow
            .sha256
            .as_deref()
            .zip(field("sha256"))
            .is_some_and(|(allowed, seen)| allowed.eq_ignore_ascii_case(seen));
        let by_signer = allow
            .signer
            .as_deref()
            .zip(field("signer"))
            .is_some_and(|(allowed, seen)| allowed == seen);
        by_hash || by_signer
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::bundle::BundleInfo;
    use crate::model::REPORT_SCHEMA_VERSION;
    use crate::provenance::Provenance;

    /// Where this program is running from, in the tests below.
    const OUR_EXE: &str = r"C:\Users\fixtureuser\Downloads\aeterna-rongroi.exe";

    /// A rule that reads the `process` collector. No such rule ships in the bundle (ADR 0010), so a
    /// test that needs one brings its own.
    const PROCESS_RULE: &str = "id: 2f0c4b1e-8a3d-4c57-9e21-6b0d7f8a1c34
title: t
description: d
status: experimental
collector: process
strength: presence
match:
  name: aeterna-rongroi.exe
retention: Running processes only.
falsepositives: [x]
author: a
date: 2026-09-12
";

    fn our_sha256() -> String {
        "b".repeat(64)
    }

    fn bundle_with(rule_yaml: &str) -> Bundle {
        let json = serde_json::json!({
            "rules": [{ "path": "process/identity/own-trace/rule.yaml", "yaml": rule_yaml }],
            "i18n": [],
        })
        .to_string();
        Bundle::from_bundle_json(&json).unwrap()
    }

    fn header() -> ReportHeader {
        ReportHeader {
            schema_version: REPORT_SCHEMA_VERSION,
            provenance: Provenance::from_parts(None, "0.0.0-test", None, None),
            rules_bundle: BundleInfo {
                schema_version: 1,
                sha256: "0".repeat(64),
                rule_count: 1,
            },
            platform: "windows".to_owned(),
            os_build: None,
            elevated: None,
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    fn process_observation(pairs: &[(&str, &str)]) -> Observation {
        Observation {
            collector: "process".to_owned(),
            fields: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), serde_json::Value::from(*v)))
                .collect(),
        }
    }

    fn process_run(observations: Vec<Observation>) -> CollectorRun {
        CollectorRun::Measured {
            collector: "process".to_owned(),
            observations,
            gaps: BTreeMap::new(),
        }
    }

    fn ours_by_path() -> SelfIdentity {
        SelfIdentity {
            exe_path: Some(OUR_EXE.to_owned()),
            exe_sha256: None,
        }
    }

    #[test]
    fn an_observation_whose_path_is_this_program_becomes_an_own_trace() {
        // Windows compares paths without regard to case, so the comparison does too.
        let ours = process_observation(&[
            ("name", "aeterna-rongroi.exe"),
            ("path", &OUR_EXE.to_uppercase()),
        ]);
        let (runs, own) = partition_own_traces(&[process_run(vec![ours.clone()])], &ours_by_path());
        assert_eq!(
            own,
            vec![OwnTraceEntry {
                collector: "process".to_owned(),
                observation: ours,
            }]
        );
        assert_eq!(runs, vec![process_run(vec![])]);
    }

    /// A copy of this program under another name is still this program: the digest says so even
    /// though the path does not.
    #[test]
    fn an_observation_whose_sha256_is_ours_becomes_an_own_trace() {
        let ours = process_observation(&[
            ("name", "renamed.exe"),
            ("path", r"C:\Temp\renamed.exe"),
            ("sha256", &our_sha256().to_uppercase()),
        ]);
        let identity = SelfIdentity {
            exe_path: Some(OUR_EXE.to_owned()),
            exe_sha256: Some(our_sha256()),
        };
        let (runs, own) = partition_own_traces(&[process_run(vec![ours.clone()])], &identity);
        assert_eq!(own.len(), 1, "{own:?}");
        assert_eq!(own[0].observation, ours);
        assert_eq!(runs, vec![process_run(vec![])]);
    }

    #[test]
    fn another_program_seen_by_the_same_collector_is_untouched() {
        let theirs = process_observation(&[
            ("name", "FiveM.exe"),
            ("path", r"C:\Users\fixtureuser\FiveM.exe"),
        ]);
        let (runs, own) =
            partition_own_traces(&[process_run(vec![theirs.clone()])], &ours_by_path());
        assert!(own.is_empty(), "{own:?}");
        assert_eq!(runs, vec![process_run(vec![theirs])]);
    }

    /// An `Unmeasured` run carries no observations, so there is nothing in it to separate.
    #[test]
    fn an_unmeasured_run_passes_through_untouched() {
        let run = CollectorRun::Unmeasured {
            collector: "process".to_owned(),
            reason: UnmeasuredReason::NotWindows,
        };
        let (runs, own) = partition_own_traces(std::slice::from_ref(&run), &ours_by_path());
        assert!(own.is_empty(), "{own:?}");
        assert_eq!(runs, vec![run]);
    }

    /// Taking the last observation out of a run must not change what the run means. The collector
    /// did look, so a rule that reads it is `NotFound` — not `Unmeasured`, which would claim the
    /// collector could not look, and not `CollectorUnavailable`, which would claim this build has
    /// no such collector (ADR 0010).
    #[test]
    fn a_run_left_empty_by_own_trace_exclusion_is_still_not_found() {
        let bundle = bundle_with(PROCESS_RULE);
        let ours = process_observation(&[("name", "aeterna-rongroi.exe"), ("path", OUR_EXE)]);
        let report = evaluate(
            &bundle,
            &[process_run(vec![ours])],
            header(),
            &ours_by_path(),
        );
        assert_eq!(report.own_traces.len(), 1);
        assert_eq!(
            report.evidence[0].state,
            EvidenceState::NotFound {
                retention: "Running processes only.".to_owned(),
            }
        );
    }

    /// The other half of the test above: the same run, when the process is somebody else's, is
    /// `Found`. Without this, "not found" could be coming from a rule that never matches at all.
    #[test]
    fn the_same_run_is_found_when_the_process_is_not_ours() {
        let bundle = bundle_with(PROCESS_RULE);
        let theirs = process_observation(&[
            ("name", "aeterna-rongroi.exe"),
            ("path", r"C:\Users\someone-else\aeterna-rongroi.exe"),
        ]);
        let report = evaluate(
            &bundle,
            &[process_run(vec![theirs])],
            header(),
            &ours_by_path(),
        );
        assert!(report.own_traces.is_empty(), "{:?}", report.own_traces);
        assert!(matches!(
            report.evidence[0].state,
            EvidenceState::Found { .. }
        ));
    }

    fn rule(extra: &str) -> Rule {
        let yaml = format!(
            "id: 7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7\ntitle: t\ndescription: d\nstatus: test\ncollector: posture\nstrength: posture\nmatch:\n  secure_boot: disabled\nretention: Current setting only.\nfalsepositives: [x]\nauthor: a\ndate: 2026-09-11\n{extra}"
        );
        serde_saphyr::from_str(&yaml).unwrap()
    }

    fn observation(pairs: &[(&str, &str)]) -> Observation {
        Observation {
            collector: "posture".to_owned(),
            fields: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), serde_json::Value::from(*v)))
                .collect(),
        }
    }

    fn measured(observations: Vec<Observation>) -> CollectorRun {
        CollectorRun::Measured {
            collector: "posture".to_owned(),
            observations,
            gaps: BTreeMap::new(),
        }
    }

    #[test]
    fn matching_observation_is_found() {
        let run = measured(vec![observation(&[("secure_boot", "disabled")])]);
        let evidence = evaluate_rule(&rule(""), &[run]);
        assert!(
            matches!(evidence.state, EvidenceState::Found { ref observations } if observations.len() == 1)
        );
    }

    #[test]
    fn measured_without_match_is_not_found_with_retention() {
        let run = measured(vec![observation(&[("secure_boot", "enabled")])]);
        let evidence = evaluate_rule(&rule(""), &[run]);
        assert_eq!(
            evidence.state,
            EvidenceState::NotFound {
                retention: "Current setting only.".to_owned()
            }
        );
    }

    #[test]
    fn gap_in_a_needed_field_is_unmeasured_not_not_found() {
        let run = CollectorRun::Measured {
            collector: "posture".to_owned(),
            observations: vec![],
            gaps: BTreeMap::from([("secure_boot".to_owned(), UnmeasuredReason::AccessDenied)]),
        };
        let evidence = evaluate_rule(&rule(""), &[run]);
        assert_eq!(
            evidence.state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied
            }
        );
    }

    #[test]
    fn unmeasured_collector_is_unmeasured() {
        let run = CollectorRun::Unmeasured {
            collector: "posture".to_owned(),
            reason: UnmeasuredReason::NotWindows,
        };
        let evidence = evaluate_rule(&rule(""), &[run]);
        assert_eq!(
            evidence.state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::NotWindows
            }
        );
    }

    #[test]
    fn missing_collector_is_unavailable() {
        let evidence = evaluate_rule(&rule(""), &[]);
        assert_eq!(
            evidence.state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::CollectorUnavailable
            }
        );
    }

    #[test]
    fn allowed_hash_is_excluded() {
        let hash = "a".repeat(64);
        let rule = rule(&format!("allow:\n  - sha256: {}\n", hash.to_uppercase()));
        let run = measured(vec![observation(&[
            ("secure_boot", "disabled"),
            ("sha256", &hash),
        ])]);
        let evidence = evaluate_rule(&rule, &[run]);
        assert!(matches!(evidence.state, EvidenceState::NotFound { .. }));
    }
}
