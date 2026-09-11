// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Turns collector runs and rules into evidence. Pure: no I/O, no clock, no platform checks.

use crate::bundle::Bundle;
use crate::model::{
    CollectorRun, Evidence, EvidenceState, Observation, Report, ReportHeader, UnmeasuredReason,
};
use crate::rules::{Rule, Status};

/// Evaluates every non-deprecated rule in `bundle` against `runs`.
pub fn evaluate(bundle: &Bundle, runs: &[CollectorRun], header: ReportHeader) -> Report {
    let evidence = bundle
        .rules()
        .iter()
        .map(|sourced| &sourced.rule)
        .filter(|rule| rule.status != Status::Deprecated)
        .map(|rule| evaluate_rule(rule, runs))
        .collect();
    Report { header, evidence }
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
