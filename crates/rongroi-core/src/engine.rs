// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Turns collector runs and rules into evidence. Pure: no I/O, no clock, no platform checks.

use crate::bundle::Bundle;
use crate::model::{
    CollectorRun, Evidence, EvidenceState, Observation, OwnTraceEntry, Report, ReportHeader,
    UnmatchedGroup, UnmeasuredReason,
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
    let active: Vec<&Rule> = bundle
        .rules()
        .iter()
        .map(|sourced| &sourced.rule)
        .filter(|rule| rule.status != Status::Deprecated)
        .collect();
    let evidence = active
        .iter()
        .map(|rule| evaluate_rule(rule, &runs))
        .collect();
    let unmatched = unmatched_observations(&runs, &active);
    Report {
        header,
        evidence,
        own_traces,
        unmatched,
    }
}

/// What the collectors saw that no rule matched, grouped by collector (ADR 0014).
///
/// This is the complement of "matched at least one rule", never the union of what each rule
/// rejected: an observation one rule matched is already evidence under that rule, and listing it
/// here as well because a second rule did not match it would show nearly everything twice.
///
/// `runs` has already had the own traces taken out of it, so an own trace is never also an unmatched
/// observation. A collector with nothing left over contributes no group rather than an empty one,
/// and a run that could not look contributes none either — it saw nothing to leave unmatched.
fn unmatched_observations(runs: &[CollectorRun], active: &[&Rule]) -> Vec<UnmatchedGroup> {
    runs.iter()
        .filter_map(|run| {
            let CollectorRun::Measured {
                collector,
                observations,
                ..
            } = run
            else {
                return None;
            };
            let observations: Vec<Observation> = observations
                .iter()
                .filter(|observation| !active.iter().any(|rule| matches(rule, observation)))
                .cloned()
                .collect();
            (!observations.is_empty()).then(|| UnmatchedGroup {
                collector: collector.clone(),
                observations,
            })
        })
        .collect()
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

/// Whether `observation` is one this rule asks to be shown.
///
/// The collector id is compared byte for byte: it is not an observation field but an identifier this
/// repository chooses, and `rules::validate_path` already requires it to be `snake_case`.
///
/// A field the rule names and the observation does not carry is not a match, and cannot be: there is
/// no way to write "this field is absent". Whether that silence is `not_found` or `unmeasured` is
/// decided by `gaps` in [`evaluate_rule`], which is keyed on the rule's `match` field **names** —
/// case folding changes values only, so `cased` changes nothing about which rules a gap reaches.
fn matches(rule: &Rule, observation: &Observation) -> bool {
    observation.collector == rule.collector
        && rule.matcher.iter().all(|(field, expected)| {
            observation.fields.get(field).is_some_and(|seen| {
                value_matches(expected, seen, rule.cased.contains(field.as_str()))
            })
        })
        && !is_allowed(rule, observation)
}

/// Whether the value an observation carries is the value a rule asked for (ADR 0025).
///
/// Strings compare without regard to **ASCII** case unless the rule listed the field in `cased`.
/// Windows compares paths and file names that way, and byte equality turns a rule that should have
/// matched into `not_found` — which the report presents as a thing looked for and not there.
///
/// Numbers, booleans and null carry no case and keep `serde_json`'s own equality, which is typed:
/// `1102` does not match `"1102"`, and does not match `1102.0` either. Arrays and objects recurse so
/// that one sentence covers every string in a rule; no collector emits either shape today.
fn value_matches(expected: &serde_json::Value, seen: &serde_json::Value, cased: bool) -> bool {
    use serde_json::Value;
    if cased {
        return expected == seen;
    }
    match (expected, seen) {
        (Value::String(expected), Value::String(seen)) => expected.eq_ignore_ascii_case(seen),
        (Value::Array(expected), Value::Array(seen)) => {
            expected.len() == seen.len()
                && std::iter::zip(expected, seen)
                    .all(|(expected, seen)| value_matches(expected, seen, false))
        }
        // Keys are names, not values, so they are compared exactly — as the `match` field names
        // themselves are, being looked up in the observation's own map.
        (Value::Object(expected), Value::Object(seen)) => {
            expected.len() == seen.len()
                && expected.iter().all(|(key, expected)| {
                    seen.get(key)
                        .is_some_and(|seen| value_matches(expected, seen, false))
                })
        }
        _ => expected == seen,
    }
}

/// Whether a rule excuses this observation.
///
/// `sha256` compares without regard to ASCII case because hex is written both ways; `signer` stays
/// exact. ADR 0025 made a rule's `match` case-insensitive and deliberately left this alone: folding
/// here widens an exclusion rather than a match, which is weakening a rule, and no collector in this
/// repository has ever emitted a `signer` field to fold.
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

    /// A second rule on the same collector, so that "matched at least one rule" can be told apart
    /// from "matched every rule".
    const FIVEM_RULE: &str = "id: 3d7b2a90-5e14-4f6c-8b03-1a2c4d5e6f70
title: t
description: d
status: experimental
collector: process
strength: presence
match:
  name: FiveM.exe
retention: Running processes only.
falsepositives: [x]
author: a
date: 2026-09-12
";

    fn our_sha256() -> String {
        "b".repeat(64)
    }

    fn bundle_with(rule_yaml: &str) -> Bundle {
        bundle_of(&[rule_yaml])
    }

    /// A bundle of `rules` in the order given, each at a path of its own.
    fn bundle_of(rules: &[&str]) -> Bundle {
        let files: Vec<serde_json::Value> = rules
            .iter()
            .enumerate()
            .map(|(i, yaml)| {
                serde_json::json!({
                    "path": format!("process/identity/rule-{i}/rule.yaml"),
                    "yaml": yaml,
                })
            })
            .collect();
        let json = serde_json::json!({ "rules": files, "i18n": [] }).to_string();
        Bundle::from_bundle_json(&json).unwrap()
    }

    /// [`FIVEM_RULE`] with an `allow` entry, under an id of its own so the two never collide.
    fn allowing(hash: &str) -> String {
        format!(
            "{}allow:\n  - sha256: {hash}\n",
            FIVEM_RULE.replace(
                "3d7b2a90-5e14-4f6c-8b03-1a2c4d5e6f70",
                "5c9e1d04-7a3b-4e82-9f61-0d2b8c4a6e13",
            )
        )
    }

    fn unmatched_process(observations: Vec<Observation>) -> Vec<UnmatchedGroup> {
        vec![UnmatchedGroup {
            collector: "process".to_owned(),
            observations,
        }]
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

    /// A collector whose observations no rule reads produces nothing a screen can show unless they
    /// are kept: evidence carries observations only inside `Found` (ADR 0014).
    #[test]
    fn an_observation_no_rule_matched_becomes_an_unmatched_observation() {
        let bundle = bundle_of(&[PROCESS_RULE]);
        let theirs = process_observation(&[("name", "FiveM.exe"), ("path", r"C:\Games\FiveM.exe")]);
        let report = evaluate(
            &bundle,
            &[process_run(vec![theirs.clone()])],
            header(),
            &ours_by_path(),
        );
        assert_eq!(report.unmatched, unmatched_process(vec![theirs]));
    }

    /// The obvious wrong implementation — treating every rule's non-match as unmatched — would list
    /// this observation, which one of the two rules did match. Unmatched is the complement of
    /// "matched at least one rule", never the union of what each rule rejected.
    #[test]
    fn an_observation_one_rule_matched_is_not_unmatched_because_another_did_not() {
        let bundle = bundle_of(&[PROCESS_RULE, FIVEM_RULE]);
        let theirs = process_observation(&[("name", "FiveM.exe"), ("path", r"C:\Games\FiveM.exe")]);
        let report = evaluate(
            &bundle,
            &[process_run(vec![theirs])],
            header(),
            &ours_by_path(),
        );
        let found: Vec<bool> = report
            .evidence
            .iter()
            .map(|item| matches!(item.state, EvidenceState::Found { .. }))
            .collect();
        assert_eq!(found, [false, true], "{:?}", report.evidence);
        assert!(report.unmatched.is_empty(), "{:?}", report.unmatched);
    }

    /// `allow` is part of what `matches` means, so an observation a rule excluded was not matched by
    /// that rule. Nothing else matched it either, and it must stay visible rather than fall between
    /// the rule and the report.
    #[test]
    fn an_observation_a_rules_allow_list_excluded_is_unmatched_not_dropped() {
        let hash = "a".repeat(64);
        let bundle = bundle_of(&[&allowing(&hash)]);
        let allowed = process_observation(&[("name", "FiveM.exe"), ("sha256", &hash)]);
        let report = evaluate(
            &bundle,
            &[process_run(vec![allowed.clone()])],
            header(),
            &ours_by_path(),
        );
        assert!(
            matches!(report.evidence[0].state, EvidenceState::NotFound { .. }),
            "{:?}",
            report.evidence[0]
        );
        assert_eq!(report.unmatched, unmatched_process(vec![allowed]));
    }

    /// Own traces are partitioned out before any rule is evaluated, so the tool's own process is in
    /// `own_traces` and never also in `unmatched` — where, with no rule reading `process`, it would
    /// otherwise land and be shown twice.
    #[test]
    fn an_own_trace_is_never_also_an_unmatched_observation() {
        let bundle = bundle_of(&[PROCESS_RULE]);
        let ours = process_observation(&[("name", "aeterna-rongroi.exe"), ("path", OUR_EXE)]);
        let theirs = process_observation(&[("name", "FiveM.exe")]);
        let report = evaluate(
            &bundle,
            &[process_run(vec![ours.clone(), theirs.clone()])],
            header(),
            &ours_by_path(),
        );
        assert_eq!(report.own_traces.len(), 1, "{:?}", report.own_traces);
        assert_eq!(report.own_traces[0].observation, ours);
        assert_eq!(report.unmatched, unmatched_process(vec![theirs]));
    }

    /// `fivem_dir` and `process` both ship without a rule. They read the machine on every scan, and
    /// everything they saw is unmatched.
    #[test]
    fn with_no_rules_at_all_every_observation_is_unmatched() {
        let bundle = bundle_of(&[]);
        let first = process_observation(&[("name", "FiveM.exe")]);
        let second = process_observation(&[("name", "steam.exe")]);
        let report = evaluate(
            &bundle,
            &[process_run(vec![first.clone(), second.clone()])],
            header(),
            &SelfIdentity::default(),
        );
        assert!(report.evidence.is_empty(), "{:?}", report.evidence);
        assert_eq!(report.unmatched, unmatched_process(vec![first, second]));
    }

    /// A collector that saw only things a rule matched, and one that could not look at all, each
    /// contribute no group — not an empty one.
    #[test]
    fn a_collector_with_nothing_unmatched_contributes_no_group() {
        let bundle = bundle_of(&[FIVEM_RULE]);
        let theirs = process_observation(&[("name", "FiveM.exe")]);
        let runs = [
            process_run(vec![theirs]),
            CollectorRun::Unmeasured {
                collector: "posture".to_owned(),
                reason: UnmeasuredReason::NotWindows,
            },
        ];
        let report = evaluate(&bundle, &runs, header(), &ours_by_path());
        assert!(report.unmatched.is_empty(), "{:?}", report.unmatched);
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

    /// A rule on a `path`, in the case the rule's author happened to type it, and one observation
    /// per collector whose path differs from it only in case.
    fn path_rule(expected: &str, extra: &str) -> Rule {
        let yaml = format!(
            "id: 4a6b8c0d-1e2f-4a3b-8c5d-6e7f8a9b0c1d\ntitle: t\ndescription: d\nstatus: experimental\ncollector: process\nstrength: presence\nmatch:\n  path: \"{expected}\"\nretention: Running processes only.\nfalsepositives: [x]\nauthor: a\ndate: 2026-09-13\n{extra}"
        );
        serde_saphyr::from_str(&yaml).unwrap()
    }

    fn found(evidence: &Evidence) -> bool {
        matches!(evidence.state, EvidenceState::Found { .. })
    }

    /// The defect ADR 0025 fixes. Windows does not care which case a path was written in; byte
    /// equality does, and the rule reported `not_found` — a thing looked for and not there.
    #[test]
    fn a_rule_matches_a_path_that_differs_only_in_case() {
        let rule = path_rule(r"C:\\Windows\\Temp\\x.exe", "");
        let run = process_run(vec![process_observation(&[(
            "path",
            r"C:\WINDOWS\Temp\X.EXE",
        )])]);
        assert!(found(&evaluate_rule(&rule, &[run])));
    }

    /// The other half: `cased` is the way back to byte equality, and it has to actually stop the
    /// match above rather than be a word the engine ignores.
    #[test]
    fn a_cased_rule_does_not_match_a_path_that_differs_only_in_case() {
        let rule = path_rule(r"C:\\Windows\\Temp\\x.exe", "cased: [path]\n");
        let run = process_run(vec![process_observation(&[(
            "path",
            r"C:\WINDOWS\Temp\X.EXE",
        )])]);
        assert_eq!(
            evaluate_rule(&rule, &[run]).state,
            EvidenceState::NotFound {
                retention: "Running processes only.".to_owned(),
            }
        );
        // …and still matches the spelling it was written in.
        let run = process_run(vec![process_observation(&[(
            "path",
            r"C:\Windows\Temp\x.exe",
        )])]);
        assert!(found(&evaluate_rule(&rule, &[run])));
    }

    /// `cased` is per field, so one rule can compare a path loosely and something else exactly.
    #[test]
    fn cased_binds_only_the_field_it_names() {
        let yaml = "id: 9f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a\ntitle: t\ndescription: d\nstatus: experimental\ncollector: process\nstrength: presence\nmatch:\n  path: \"C:\\\\Games\\\\FiveM.exe\"\n  name: fivem.exe\ncased: [name]\nretention: Running processes only.\nfalsepositives: [x]\nauthor: a\ndate: 2026-09-13\n";
        let rule: Rule = serde_saphyr::from_str(yaml).unwrap();
        let loose_path =
            process_observation(&[("path", r"c:\games\fivem.exe"), ("name", "fivem.exe")]);
        assert!(found(&evaluate_rule(
            &rule,
            &[process_run(vec![loose_path])]
        )));
        let loose_name =
            process_observation(&[("path", r"C:\Games\FiveM.exe"), ("name", "FiveM.exe")]);
        assert!(!found(&evaluate_rule(
            &rule,
            &[process_run(vec![loose_name])]
        )));
    }

    /// What the ASCII fold does and does not reach. A Thai user folder passes through unchanged and
    /// the ASCII part of the path still folds; a non-ASCII letter that differs in case does not
    /// match, and this test is the record of that limit rather than a wish that it were otherwise.
    #[test]
    fn a_non_ascii_path_folds_in_its_ascii_part_only() {
        let rule = path_rule(r"C:\\Users\\สมชาย\\Downloads\\loader.exe", "");
        let run = process_run(vec![process_observation(&[(
            "path",
            r"C:\USERS\สมชาย\DOWNLOADS\LOADER.EXE",
        )])]);
        assert!(found(&evaluate_rule(&rule, &[run])));

        let rule = path_rule(r"C:\\Users\\Sömchai\\loader.exe", "");
        let run = process_run(vec![process_observation(&[(
            "path",
            r"C:\Users\SÖMCHAI\loader.exe",
        )])]);
        assert!(
            !found(&evaluate_rule(&rule, &[run])),
            "Ö and ö are not folded; the fold is ASCII-only (ADR 0025)"
        );
    }

    /// Folding strings must not start folding types together. A rule that says the number 1102 asks
    /// for the number, and an observation carrying the text `1102` is a different fact.
    #[test]
    fn a_number_is_not_compared_as_a_string() {
        let yaml = "id: 1b2c3d4e-5f60-4718-9a2b-3c4d5e6f7081\ntitle: t\ndescription: d\nstatus: experimental\ncollector: process\nstrength: presence\nmatch:\n  event_id: 1102\nretention: Running processes only.\nfalsepositives: [x]\nauthor: a\ndate: 2026-09-13\n";
        let rule: Rule = serde_saphyr::from_str(yaml).unwrap();
        let text = Observation {
            collector: "process".to_owned(),
            fields: BTreeMap::from([("event_id".to_owned(), serde_json::json!("1102"))]),
        };
        assert!(!found(&evaluate_rule(&rule, &[process_run(vec![text])])));
        let number = Observation {
            collector: "process".to_owned(),
            fields: BTreeMap::from([("event_id".to_owned(), serde_json::json!(1102))]),
        };
        assert!(found(&evaluate_rule(&rule, &[process_run(vec![number])])));
    }

    /// A field the rule names and the observation does not carry stays a non-match, with `cased` and
    /// without it. `is_some_and` over the lookup replaced an `Option` comparison; this holds it.
    #[test]
    fn a_field_the_observation_does_not_carry_is_not_a_match() {
        for extra in ["", "cased: [path]\n"] {
            let rule = path_rule(r"C:\\Windows\\Temp\\x.exe", extra);
            let run = process_run(vec![process_observation(&[("name", "x.exe")])]);
            assert_eq!(
                evaluate_rule(&rule, &[run]).state,
                EvidenceState::NotFound {
                    retention: "Running processes only.".to_owned(),
                },
                "with `{extra}`"
            );
        }
    }

    /// Matching is one function, so an observation a rule matched only because of the fold is
    /// evidence under that rule and not also an unmatched observation (ADR 0014).
    #[test]
    fn an_observation_matched_by_the_fold_is_not_also_unmatched() {
        let bundle = bundle_of(&[FIVEM_RULE]);
        let theirs = process_observation(&[("name", "fivem.EXE")]);
        let report = evaluate(
            &bundle,
            &[process_run(vec![theirs])],
            header(),
            &ours_by_path(),
        );
        assert!(found(&report.evidence[0]), "{:?}", report.evidence[0]);
        assert!(report.unmatched.is_empty(), "{:?}", report.unmatched);
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
