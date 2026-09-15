// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Turns collector runs and rules into evidence. Pure: no I/O, no clock, no platform checks.

use crate::bundle::Bundle;
use crate::model::{
    CollectorRun, DiscriminatorGaps, Evidence, EvidenceState, Observation, OwnTraceEntry, Report,
    ReportHeader, UnmatchedGroup, UnmeasuredReason,
};
use crate::rules::{MatchKey, Operator, Rule, Status};

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
                discriminator_gaps,
                ..
            } = run
            else {
                return None;
            };
            let observations: Vec<Observation> = observations
                .iter()
                .filter(|observation| {
                    !active
                        .iter()
                        .any(|rule| matches_in_run(rule, observation, discriminator_gaps))
                })
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
            discriminator_gaps,
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
            discriminator_gaps: discriminator_gaps.clone(),
        });
    }
    (kept, own_traces)
}

/// Evaluates one rule. Used by [`evaluate`] and by fixture checks in `cargo xtask check-rules`.
pub fn evaluate_rule(rule: &Rule, runs: &[CollectorRun]) -> Evidence {
    // Every unmeasured result goes through here, so a reason the rule declared in `unmeasured_when`
    // is marked expected once, whichever of the three ways it arose (ADR 0027).
    let unmeasured = |reason: UnmeasuredReason| EvidenceState::Unmeasured {
        reason,
        expected: rule.expects_unmeasured(reason),
    };
    let state = match runs.iter().find(|run| run.collector() == rule.collector) {
        None => unmeasured(UnmeasuredReason::CollectorUnavailable),
        Some(CollectorRun::Unmeasured { reason, .. }) => unmeasured(*reason),
        Some(CollectorRun::Measured {
            observations,
            gaps,
            discriminator_gaps,
            ..
        }) => {
            // Checked before anything is matched, and this ordering is the whole of ADR 0029's
            // `exists: false` answer. That operator is satisfied by a field that is not there, and a
            // field the collector could not read is not there either — so a rule asking "this path
            // is absent" about an unreadable path would be `Found`, and the report would say "we
            // looked and there is no path" about a path nobody could read. Every other operator
            // needs the field to be present, so for those the gap can be, and is, checked after.
            if let Some(reason) = absence_fields(rule).find_map(|field| gaps.get(field)) {
                return evidence(rule, unmeasured(*reason));
            }
            // A gap confined to one discriminator value cannot take that early return: an
            // observation from a place that *was* read lacks a field because it is not there, and
            // that is a measured answer. What it does instead is keep an observation from the
            // unreadable place from satisfying the absence — `matches_in_run` — so the same
            // guarantee holds for exactly the observations the gap is about (ADR 0044).
            let matched: Vec<Observation> = observations
                .iter()
                .filter(|observation| matches_in_run(rule, observation, discriminator_gaps))
                .cloned()
                .collect();
            if !matched.is_empty() {
                EvidenceState::Found {
                    observations: matched,
                }
            } else if let Some(reason) = rule.match_fields().find_map(|field| gaps.get(field)) {
                // Nothing matched, but a field the rule needs was never read: "not found" would lie.
                unmeasured(*reason)
            } else if let Some(reason) = discriminator_gaps
                .iter()
                .filter(|place| could_match_there(rule, place))
                .find_map(|place| rule.match_fields().find_map(|field| place.gaps.get(field)))
            {
                // The same lie, confined to one place: a place this rule could have matched in was
                // not read. A place the rule's own `match` rules out is not consulted (ADR 0044).
                unmeasured(*reason)
            } else {
                EvidenceState::NotFound {
                    retention: rule.retention.clone(),
                }
            }
        }
    };
    evidence(rule, state)
}

/// Wraps one rule's state as its evidence.
fn evidence(rule: &Rule, state: EvidenceState) -> Evidence {
    Evidence {
        rule_id: rule.id.clone(),
        collector: rule.collector.clone(),
        strength: rule.strength,
        state,
    }
}

/// The fields a rule asks to be **absent** — `<field>|exists: false`.
///
/// These are the only fields whose condition an observation can satisfy by carrying nothing, which
/// is why [`evaluate_rule`] consults `gaps` for them before it matches anything.
fn absence_fields(rule: &Rule) -> impl Iterator<Item = &str> {
    rule.conditions().filter_map(|(key, value)| match key {
        MatchKey::Known {
            field,
            operator: Operator::Exists,
        } if value == &serde_json::Value::Bool(false) => Some(field),
        _ => None,
    })
}

/// Whether `observation` is one this rule asks to be shown.
///
/// The collector id is compared byte for byte: it is not an observation field but an identifier this
/// repository chooses, and `rules::validate_path` already requires it to be `snake_case`.
///
/// Every condition must hold — `match` is a conjunction, and ADR 0029 left it one. A field the rule
/// names and the observation does not carry satisfies only `<field>|exists: false`; for every other
/// operator it is not a match. Whether that silence is `not_found` or `unmeasured` is decided by
/// `gaps` in [`evaluate_rule`], which is keyed on the rule's `match` field **names** as split out by
/// `rules::parse_match_key` — never on the `match` key, so an operator suffix does not take a field
/// out of the gap lookup (ADR 0025's objection to a suffix, answered in ADR 0029).
fn matches(rule: &Rule, observation: &Observation) -> bool {
    unmet_conditions(rule, observation).is_some_and(|mut unmet| unmet.next().is_none())
        && !is_allowed(rule, observation)
}

/// [`matches`], within a run whose discriminator gaps are `places`.
///
/// An observation about a place that could not be read does not satisfy `<field>|exists: false` for a
/// field listed in that place's gaps: the field may be missing because it was never read. This is
/// ADR 0029's reason for checking run-wide gaps before an absence condition, applied to the one place
/// the gap is about rather than to the whole run (ADR 0044). Every other condition needs the field
/// to be present, so a gap cannot make it true and needs no such exclusion.
fn matches_in_run(rule: &Rule, observation: &Observation, places: &[DiscriminatorGaps]) -> bool {
    matches(rule, observation)
        && !places.iter().any(|place| {
            place.describes(observation)
                && absence_fields(rule).any(|field| place.gaps.contains_key(field))
        })
}

/// Whether `rule` could match an observation about the place `gaps` describes — whether every one of
/// the rule's conditions on the discriminator holds for the discriminator's value there.
///
/// A rule with no condition on the discriminator could match anywhere, so every place's gaps reach
/// it. A rule whose `location: plugins` cannot be satisfied by `location: enhanced_exe` could never
/// match an observation from there, so whatever was not read there is not a question this rule
/// asked. The comparison is the one `match` itself makes — the ASCII fold, `cased`, value lists and
/// operators included — so the two cannot disagree about which places a rule reaches.
fn could_match_there(rule: &Rule, gaps: &DiscriminatorGaps) -> bool {
    rule.conditions()
        .filter(|(key, _)| key.field() == gaps.discriminator)
        .all(|(key, expected)| match key {
            MatchKey::Known { field, operator } => condition_matches(
                operator,
                expected,
                Some(&gaps.value),
                rule.cased.contains(field),
            ),
            // `rules::validate` refuses such a key. If one arrived, reaching the place is the answer
            // that leaves the rule `unmeasured` rather than `not_found`.
            MatchKey::UnknownOperator { .. } => true,
        })
}

/// The fields of `rule`'s `match` conditions that `observation` fails to satisfy, one entry per
/// unsatisfied condition, or `None` when the observation belongs to another collector and the question
/// does not arise.
///
/// [`matches`] is the "none" case of this, and [`confronts`] the "at most one" one.
fn unmet_conditions<'r>(
    rule: &'r Rule,
    observation: &'r Observation,
) -> Option<impl Iterator<Item = &'r str> + 'r> {
    (observation.collector == rule.collector).then(|| {
        rule.conditions().filter_map(|(key, expected)| {
            let unmet = match key {
                MatchKey::Known { field, operator } => !condition_matches(
                    operator,
                    expected,
                    observation.fields.get(field),
                    rule.cased.contains(field),
                ),
                // `rules::validate` refuses such a key, so no loaded bundle holds one. If one ever
                // reached here it must not be skipped: skipping a condition drops a restriction and
                // widens the rule past what its title claims.
                MatchKey::UnknownOperator { .. } => true,
            };
            unmet.then(|| key.field())
        })
    })
}

/// Whether `observation` came close enough to firing `rule` to be evidence that the rule was tried.
///
/// **Two conditions, and the second is what makes this worth having.** The observation must come
/// within one unsatisfied condition of matching, *and* it must carry every field the rule names —
/// excepting the fields a rule asks to be absent, which an observation satisfies by carrying
/// nothing. Without the second condition a one-condition rule would be confronted by every
/// observation its collector produced, including one that carries none of the rule's fields at all,
/// and the check would certify most loudly exactly where it knows least.
///
/// **The one unsatisfied condition may not be on `discriminator`**, the field the rule's collector
/// declares says which place an observation is about (ADR 0044). An observation that differs from a
/// rule there alone is about another place: it was asked the rule's question about somewhere the rule
/// does not look, and a misspelt place in the rule would go on being "confronted" by it for ever —
/// measured on `fivem_dir`'s valid-signature plugin rule, ADR 0033 as amended on 2026-09-14. The engine
/// does not know collectors, so the caller passes the discriminator; `None` is the definition as
/// ADR 0033 first wrote it.
///
/// `cargo xtask check-baseline` asks this of every rule against every baseline observation. A rule
/// no baseline confronts has never been compared to anything of its own shape, and is quiet there
/// for a reason that says nothing about the rule (ADR 0033). The predicate lives here rather than in
/// the gate because a second implementation of "does this condition hold" would drift from the one
/// the product uses, which is the failure ADR 0017 exists to prevent.
///
/// `allow` is deliberately not consulted: an observation a rule matched and then allowed is still an
/// observation the rule was compared against.
pub fn confronts(rule: &Rule, observation: &Observation, discriminator: Option<&str>) -> bool {
    let Some(unmet) = unmet_conditions(rule, observation) else {
        return false;
    };
    let close = match unmet.take(2).collect::<Vec<_>>().as_slice() {
        [] => true,
        [field] => Some(*field) != discriminator,
        _ => false,
    };
    if !close {
        return false;
    }
    let absent: Vec<&str> = absence_fields(rule).collect();
    rule.match_fields()
        .all(|field| absent.contains(&field) || observation.fields.contains_key(field))
}

/// Whether one `match` entry holds for the value an observation carries, or does not carry.
fn condition_matches(
    operator: Operator,
    expected: &serde_json::Value,
    seen: Option<&serde_json::Value>,
    cased: bool,
) -> bool {
    if operator == Operator::Exists {
        return expected.as_bool() == Some(seen.is_some());
    }
    seen.is_some_and(|seen| {
        any_of(expected, |expected| {
            compare(operator, expected, seen, cased)
        })
    })
}

/// Applies `compare` to each element of a list value, or to a lone value.
///
/// A list in `match` means **or**, which is what a list means in Sigma's `detection` and what makes
/// one rule out of what would otherwise be one rule per value (ADR 0029). Only the operators whose
/// `takes_a_list` is true reach here with a list; `rules::validate` refuses the others.
fn any_of(expected: &serde_json::Value, compare: impl Fn(&serde_json::Value) -> bool) -> bool {
    match expected {
        serde_json::Value::Array(list) => list.iter().any(compare),
        single => compare(single),
    }
}

/// Compares one expected value to the one an observation carries, for every operator but `exists`.
fn compare(
    operator: Operator,
    expected: &serde_json::Value,
    seen: &serde_json::Value,
    cased: bool,
) -> bool {
    match operator {
        Operator::Equals => value_matches(expected, seen, cased),
        Operator::StartsWith | Operator::EndsWith | Operator::Contains => {
            text_matches(operator, expected, seen, cased)
        }
        Operator::GreaterThan | Operator::AtLeast | Operator::LessThan | Operator::AtMost => {
            ordering_of(expected, seen).is_some_and(|ordering| accepts(operator, ordering))
        }
        // Handled by `condition_matches` before a value is looked at, because it is the one operator
        // that has an answer when there is no value.
        Operator::Exists => false,
    }
}

/// Whether the text an observation carries begins with, ends with or holds the text a rule names.
///
/// Both sides must be strings: a rule comparing text to a number is refused by `check-rules`, and if
/// one arrived it is not a match rather than a coercion (ADR 0025 settled that for equality).
///
/// Case folds ASCII unless the field is in `cased`, which is the whole of what a string operator
/// inherits from ADR 0025 — the bytes are compared with `eq_ignore_ascii_case`, so `startswith` on
/// `C:\Users\` matches `c:\users\somchai\…` exactly as equality on a whole path does.
///
/// **These are text operators, not path operators.** `startswith` is a byte prefix and `contains` a
/// byte substring; neither knows what a directory separator is. ADR 0029 says why, and says what a
/// rule author has to write instead.
fn text_matches(
    operator: Operator,
    expected: &serde_json::Value,
    seen: &serde_json::Value,
    cased: bool,
) -> bool {
    let (Some(expected), Some(seen)) = (expected.as_str(), seen.as_str()) else {
        return false;
    };
    let (needle, haystack) = (expected.as_bytes(), seen.as_bytes());
    // An empty needle would make the condition true of every observation — a rule broader than any
    // title it could carry. `rules::validate` refuses one; this is the answer if one arrived.
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let same = |left: &[u8], right: &[u8]| {
        if cased {
            left == right
        } else {
            left.eq_ignore_ascii_case(right)
        }
    };
    match operator {
        Operator::StartsWith => same(&haystack[..needle.len()], needle),
        Operator::EndsWith => same(&haystack[haystack.len() - needle.len()..], needle),
        Operator::Contains => haystack
            .windows(needle.len())
            .any(|window| same(window, needle)),
        _ => false,
    }
}

/// Whether an ordering satisfies the operator that asked for it.
fn accepts(operator: Operator, ordering: std::cmp::Ordering) -> bool {
    use std::cmp::Ordering::{Equal, Greater, Less};
    match operator {
        Operator::GreaterThan => ordering == Greater,
        Operator::AtLeast => matches!(ordering, Greater | Equal),
        Operator::LessThan => ordering == Less,
        Operator::AtMost => matches!(ordering, Less | Equal),
        _ => false,
    }
}

/// How the value an observation carries sorts against the one the rule names, or `None` when the two
/// cannot be put in order at all.
///
/// Two kinds are ordered, and nothing else: **numbers**, and **RFC 3339 timestamps**, which are
/// parsed rather than compared as text. The collectors write a timestamp with
/// `jiff::Timestamp::to_string`, which omits a fraction of a second that is zero and trims trailing
/// zeros from one that is not — so `2020-01-01T00:00:00.5Z` and `2020-01-01T00:00:00Z` have
/// different shapes, and comparing them as text puts the later instant first, because `.` sorts
/// before `Z`. That is measured, not assumed (ADR 0029).
///
/// A pair that does not parse, or a number against a string, is `None`: not a match, never a
/// coercion, and `check-rules` refuses the rule that could produce it.
fn ordering_of(
    expected: &serde_json::Value,
    seen: &serde_json::Value,
) -> Option<std::cmp::Ordering> {
    use serde_json::Value;
    match (expected, seen) {
        (Value::Number(expected), Value::Number(seen)) => number_ordering(expected, seen),
        (Value::String(expected), Value::String(seen)) => {
            let expected: jiff::Timestamp = expected.parse().ok()?;
            let seen: jiff::Timestamp = seen.parse().ok()?;
            Some(seen.cmp(&expected))
        }
        _ => None,
    }
}

/// How two JSON numbers sort, without going through `f64` when both fit an integer.
///
/// A record id or a byte count can exceed the 53 bits an `f64` holds exactly, and two such values
/// one apart would compare equal after the conversion.
fn number_ordering(
    expected: &serde_json::Number,
    seen: &serde_json::Number,
) -> Option<std::cmp::Ordering> {
    if let (Some(expected), Some(seen)) = (expected.as_i64(), seen.as_i64()) {
        return Some(seen.cmp(&expected));
    }
    if let (Some(expected), Some(seen)) = (expected.as_u64(), seen.as_u64()) {
        return Some(seen.cmp(&expected));
    }
    seen.as_f64()?.partial_cmp(&expected.as_f64()?)
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
///
/// A **top-level** array in `match` no longer reaches here as a value: since ADR 0029 it means "any
/// of these", and `any_of` has already split it. The recursive arm below is for an array nested
/// inside one, which no collector emits and no rule writes.
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
/// Both identities are hex digests and compare without regard to ASCII case, because hex is written
/// both ways. Folding here does not widen an exclusion the way folding a name would: two digests that
/// differ only in case are the same digest. There is no name to compare — not the file's and, since
/// ADR 0035, not the signer's either.
fn is_allowed(rule: &Rule, observation: &Observation) -> bool {
    let field = |name: &str| {
        observation
            .fields
            .get(name)
            .and_then(serde_json::Value::as_str)
    };
    let same = |allowed: Option<&str>, seen: &str| {
        allowed
            .zip(field(seen))
            .is_some_and(|(allowed, seen)| allowed.eq_ignore_ascii_case(seen))
    };
    rule.allow.iter().any(|allow| {
        same(allow.sha256.as_deref(), "sha256")
            || same(allow.signer_cert_sha256.as_deref(), "signer_cert_sha256")
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
            boot_time: crate::model::BootTime::default(),
            profiles_directory: None,
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
            discriminator_gaps: Vec::new(),
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

    /// `process` ships without a rule (ADR 0010), and `fivem_dir` did until ADR 0036. Such a collector
    /// reads the machine on every scan, and everything it saw is unmatched.
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

    /// `rule` with its `match` block replaced, for the tests that need more than one condition.
    fn rule_matching(block: &str) -> Rule {
        let yaml = format!(
            "id: 7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7\ntitle: t\ndescription: d\nstatus: test\ncollector: posture\nstrength: posture\nmatch:\n{block}\nretention: Current setting only.\nfalsepositives: [x]\nauthor: a\ndate: 2026-09-11\n"
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
            discriminator_gaps: Vec::new(),
        }
    }

    /// A rule with one condition, against an observation carrying that field with another value.
    /// This is the ordinary shape: the baseline was asked the rule's question and answered no.
    #[test]
    fn an_observation_one_value_away_confronts_the_rule() {
        assert!(confronts(
            &rule(""),
            &observation(&[("secure_boot", "enabled")]),
            None
        ));
    }

    /// The case the second half of the predicate exists for. The rule has one condition, so counting
    /// unsatisfied conditions alone would call this a confrontation — the observation cannot fail
    /// more than one. It carries none of the rule's fields, so it was never asked the question.
    #[test]
    fn an_observation_without_the_rules_field_does_not_confront_it() {
        assert!(!confronts(
            &rule(""),
            &observation(&[("tpm", "present")]),
            None
        ));
    }

    /// The shape `check-baseline` was blind to: a three-condition rule against an observation that
    /// carries all three fields and matches none of them. Three unsatisfied is not "came close".
    #[test]
    fn an_observation_failing_more_than_one_condition_does_not_confront_the_rule() {
        let rule = rule_matching(
            "  provider: Microsoft-Windows-Eventlog\n  channel: Security\n  event_id: 1102",
        );
        let seen = observation(&[
            ("provider", "Microsoft-Windows-LanguagePackSetup"),
            ("channel", "Microsoft-Windows-LanguagePackSetup/Operational"),
            ("event_id", "3001"),
        ]);
        assert!(!confronts(&rule, &seen, None));
    }

    /// The same rule against the same channel and provider, differing only in the event id — what a
    /// real Security log holds, and what would end that rule's row in `rules/unconfronted.csv`.
    #[test]
    fn an_observation_matching_all_but_one_condition_confronts_the_rule() {
        let rule = rule_matching(
            "  provider: Microsoft-Windows-Eventlog\n  channel: Security\n  event_id: 1102",
        );
        let seen = observation(&[
            ("provider", "Microsoft-Windows-Eventlog"),
            ("channel", "Security"),
            ("event_id", "1100"),
        ]);
        assert!(confronts(&rule, &seen, None));
    }

    /// A matching observation confronts its rule too: `confronts` is the wider question, and a rule
    /// that fired is certainly one that was tried.
    #[test]
    fn a_matching_observation_confronts_the_rule() {
        assert!(confronts(
            &rule(""),
            &observation(&[("secure_boot", "disabled")]),
            None
        ));
    }

    /// Another collector's observation is not an answer to this rule at all.
    #[test]
    fn an_observation_from_another_collector_does_not_confront_the_rule() {
        let mut seen = observation(&[("secure_boot", "enabled")]);
        seen.collector = "evtx".to_owned();
        assert!(!confronts(&rule(""), &seen, None));
    }

    /// ADR 0033, amended 2026-09-14. The baseline's `FiveM.exe` differs from the valid-signature
    /// plugins rule in `location` alone. Without a discriminator that counts as a confrontation; with
    /// one it does not, because the observation is about another place.
    #[test]
    fn a_near_miss_in_the_discriminator_alone_does_not_confront_the_rule() {
        let rule = fivem_rule("  location: plugins\n  signature: valid\n");
        let exe = fivem_observation(serde_json::json!({
            "location": "legacy_exe",
            "path": r"C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.exe",
            "signature": "valid",
        }));
        assert!(confronts(&rule, &exe, None));
        assert!(!confronts(&rule, &exe, Some("location")));
    }

    /// The positive twin: in the same place and one signature answer away, the observation was asked
    /// the rule's question and answered no, discriminator or not. And a match confronts, as ever.
    #[test]
    fn a_near_miss_in_another_field_still_confronts_the_rule_that_has_a_discriminator() {
        let rule = fivem_rule("  location: plugins\n  signature: valid\n");
        let plugin = |signature: &str| {
            fivem_observation(serde_json::json!({
                "location": "plugins",
                "path": r"C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.app\plugins\x.dll",
                "signature": signature,
            }))
        };
        assert!(confronts(
            &rule,
            &plugin("no_embedded_signature"),
            Some("location")
        ));
        assert!(confronts(&rule, &plugin("valid"), Some("location")));
    }

    /// A discriminator the rule does not name changes nothing: the one unsatisfied condition is
    /// elsewhere, so the definition is ADR 0033's.
    #[test]
    fn a_rule_without_a_condition_on_the_discriminator_is_confronted_as_before() {
        let rule = fivem_rule("  path|exists: true\n  signature|exists: false\n");
        let exe = fivem_observation(serde_json::json!({
            "location": "legacy_exe",
            "path": r"C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.exe",
            "signature": "valid",
        }));
        assert!(confronts(&rule, &exe, Some("location")));
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
            discriminator_gaps: Vec::new(),
        };
        let evidence = evaluate_rule(&rule(""), &[run]);
        assert_eq!(
            evidence.state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                expected: false
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
                reason: UnmeasuredReason::NotWindows,
                expected: false
            }
        );
    }

    /// `unmeasured_when` names the reasons the rule's author said happen on ordinary machines. The
    /// engine records which of the two a result is; the view decides what to do with it (ADR 0027).
    #[test]
    fn a_declared_reason_is_expected_and_an_undeclared_one_is_not() {
        let rule = rule("unmeasured_when: [access_denied]\n");
        let declared = CollectorRun::Unmeasured {
            collector: "posture".to_owned(),
            reason: UnmeasuredReason::AccessDenied,
        };
        assert_eq!(
            evaluate_rule(&rule, &[declared]).state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                expected: true
            }
        );
        let undeclared = CollectorRun::Unmeasured {
            collector: "posture".to_owned(),
            reason: UnmeasuredReason::ReadFailed,
        };
        assert_eq!(
            evaluate_rule(&rule, &[undeclared]).state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::ReadFailed,
                expected: false
            }
        );
    }

    /// The other two ways a rule becomes unmeasured answer the same way: a gap in a field the rule
    /// needs, and no run for its collector at all.
    #[test]
    fn a_declared_reason_is_expected_whichever_way_it_arose() {
        let rule = rule("unmeasured_when: [access_denied, collector_unavailable]\n");
        let gap = CollectorRun::Measured {
            collector: "posture".to_owned(),
            observations: vec![],
            gaps: BTreeMap::from([("secure_boot".to_owned(), UnmeasuredReason::AccessDenied)]),
            discriminator_gaps: Vec::new(),
        };
        assert_eq!(
            evaluate_rule(&rule, &[gap]).state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                expected: true
            }
        );
        assert_eq!(
            evaluate_rule(&rule, &[]).state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::CollectorUnavailable,
                expected: true
            }
        );
    }

    /// A rule with no `unmeasured_when` expects nothing, which is the state every rule was in while
    /// the field was parsed and read by nothing.
    #[test]
    fn a_rule_that_declares_nothing_expects_nothing() {
        let run = CollectorRun::Unmeasured {
            collector: "posture".to_owned(),
            reason: UnmeasuredReason::AccessDenied,
        };
        assert_eq!(
            evaluate_rule(&rule(""), &[run]).state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                expected: false
            }
        );
    }

    #[test]
    fn missing_collector_is_unavailable() {
        let evidence = evaluate_rule(&rule(""), &[]);
        assert_eq!(
            evidence.state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::CollectorUnavailable,
                expected: false
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

    /// ADR 0035: the certificate's hash excuses an observation, in either case; its signer's name
    /// never does, and a certificate hash in the observation's `sha256` field is not the same claim.
    #[test]
    fn an_allowed_signing_certificate_is_excluded_and_a_signer_name_is_not() {
        let cert = "b".repeat(64);
        let rule = rule(&format!(
            "allow:\n  - signer_cert_sha256: {}\n",
            cert.to_uppercase()
        ));
        let signed_by = |cert: &str| {
            measured(vec![observation(&[
                ("secure_boot", "disabled"),
                ("signer", "Example Corp"),
                ("signer_cert_sha256", cert),
            ])])
        };
        let excluded = evaluate_rule(&rule, &[signed_by(&cert)]);
        assert!(matches!(excluded.state, EvidenceState::NotFound { .. }));

        let other = evaluate_rule(&rule, &[signed_by(&"c".repeat(64))]);
        assert!(
            matches!(other.state, EvidenceState::Found { .. }),
            "{other:?}"
        );

        let hash_field = evaluate_rule(
            &rule,
            &[measured(vec![observation(&[
                ("secure_boot", "disabled"),
                ("sha256", &cert),
            ])])],
        );
        assert!(matches!(hash_field.state, EvidenceState::Found { .. }));
    }

    #[test]
    fn a_signer_name_in_allow_does_not_parse() {
        let yaml = "id: 8f2e1a47-0b6c-4d93-9a15-2c7e4f6b8d03\ntitle: t\ndescription: d\nstatus: experimental\ncollector: posture\nstrength: posture\nmatch:\n  secure_boot: disabled\nretention: r\nallow:\n  - signer: Example Corp\nfalsepositives: [x]\nauthor: a\ndate: 2026-09-13\n";
        assert!(serde_saphyr::from_str::<Rule>(yaml).is_err());
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

    // ------------------------------------------------------------------------------------------
    // ADR 0029: the four operators, each with a match, a non-match, its `gaps` case and, where the
    // operator compares text, what `cased` does to it.
    // ------------------------------------------------------------------------------------------

    /// A rule on the `evtx` collector carrying the `match` block given. No rule ships for that
    /// collector, so every operator test brings its own; the fields are the ones `evtx` declares.
    fn evtx_rule(match_block: &str) -> Rule {
        let yaml = format!(
            "id: 8f2e1a47-0b6c-4d93-9a15-2c7e4f6b8d03\ntitle: t\ndescription: d\nstatus: experimental\ncollector: evtx\nstrength: context\nmatch:\n{match_block}retention: What the logs still hold.\nfalsepositives: [x]\nauthor: a\ndate: 2026-09-13\n"
        );
        serde_saphyr::from_str(&yaml).expect("the test rule parses")
    }

    /// One `evtx` observation from JSON, so a test can carry a number, a boolean or a string.
    fn evtx_observation(fields: serde_json::Value) -> Observation {
        Observation {
            collector: "evtx".to_owned(),
            fields: serde_json::from_value(fields).expect("the test fields are an object"),
        }
    }

    fn evtx_run(observations: Vec<Observation>) -> CollectorRun {
        CollectorRun::Measured {
            collector: "evtx".to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps: Vec::new(),
        }
    }

    /// A run that saw nothing because `field` could not be read.
    fn evtx_gap(field: &str) -> CollectorRun {
        CollectorRun::Measured {
            collector: "evtx".to_owned(),
            observations: vec![],
            gaps: BTreeMap::from([(field.to_owned(), UnmeasuredReason::ReadFailed)]),
            discriminator_gaps: Vec::new(),
        }
    }

    fn not_found(evidence: &Evidence) -> bool {
        matches!(evidence.state, EvidenceState::NotFound { .. })
    }

    fn unmeasured(evidence: &Evidence) -> bool {
        matches!(evidence.state, EvidenceState::Unmeasured { .. })
    }

    /// A list means **or**: one rule where six would otherwise be six rules, six ids and six
    /// `falsepositives` lists to keep in step.
    #[test]
    fn a_value_list_matches_any_of_its_values() {
        let rule = evtx_rule("  event_id: [1102, 104]\n");
        for id in [1102, 104] {
            let run = evtx_run(vec![evtx_observation(serde_json::json!({
                "event_id": id
            }))]);
            assert!(found(&evaluate_rule(&rule, &[run])), "event_id {id}");
        }
    }

    #[test]
    fn a_value_list_does_not_match_a_value_outside_it() {
        let rule = evtx_rule("  event_id: [1102, 104]\n");
        let run = evtx_run(vec![evtx_observation(serde_json::json!({
            "event_id": 4624
        }))]);
        assert!(not_found(&evaluate_rule(&rule, &[run])));
    }

    /// Every string in a list folds ASCII case, as a lone string does (ADR 0025).
    #[test]
    fn a_string_in_a_list_folds_case_unless_the_field_is_cased() {
        let folding = evtx_rule("  channel: [Security, System]\n");
        let exact = evtx_rule("  channel: [Security, System]\ncased: [channel]\n");
        let run = || {
            evtx_run(vec![evtx_observation(serde_json::json!({
                "channel": "SECURITY"
            }))])
        };
        assert!(found(&evaluate_rule(&folding, &[run()])));
        assert!(not_found(&evaluate_rule(&exact, &[run()])));
    }

    #[test]
    fn a_gap_reaches_a_rule_whose_only_condition_is_a_list() {
        let rule = evtx_rule("  event_id: [1102, 104]\n");
        assert!(unmeasured(&evaluate_rule(&rule, &[evtx_gap("event_id")])));
    }

    /// `rejected|gt: 0` is the rule the collectors were papering over with `intact`.
    #[test]
    fn gt_matches_a_larger_number_and_not_an_equal_one() {
        let rule = evtx_rule("  rejected|gt: 0\n");
        let one = evtx_run(vec![evtx_observation(serde_json::json!({ "rejected": 1 }))]);
        let none = evtx_run(vec![evtx_observation(serde_json::json!({ "rejected": 0 }))]);
        assert!(found(&evaluate_rule(&rule, &[one])));
        assert!(not_found(&evaluate_rule(&rule, &[none])));
    }

    /// The three other ordinal operators at their boundary, where an off-by-one would hide.
    #[test]
    fn the_ordinal_operators_sit_where_their_names_say() {
        for (block, matching, missing) in [
            ("  entries|gte: 2\n", 2, 1),
            ("  entries|lt: 2\n", 1, 2),
            ("  entries|lte: 2\n", 2, 3),
        ] {
            let rule = evtx_rule(block);
            let run = |value: i64| {
                evtx_run(vec![evtx_observation(
                    serde_json::json!({ "entries": value }),
                )])
            };
            assert!(found(&evaluate_rule(&rule, &[run(matching)])), "{block}");
            assert!(not_found(&evaluate_rule(&rule, &[run(missing)])), "{block}");
        }
    }

    /// Timestamps are put in order by parsing both sides, not by comparing their text.
    #[test]
    fn a_timestamp_comparison_orders_instants() {
        let rule = evtx_rule("  oldest_record_time|gt: \"2026-01-01T00:00:00Z\"\n");
        let later = evtx_run(vec![evtx_observation(serde_json::json!({
            "oldest_record_time": "2026-09-13T10:00:00Z"
        }))]);
        let earlier = evtx_run(vec![evtx_observation(serde_json::json!({
            "oldest_record_time": "2025-12-31T23:59:59Z"
        }))]);
        assert!(found(&evaluate_rule(&rule, &[later])));
        assert!(not_found(&evaluate_rule(&rule, &[earlier])));
    }

    /// Why the comparison parses. `jiff::Timestamp::to_string` writes a fraction of a second only
    /// when there is one, so the collectors emit two shapes; `.` sorts before `Z`, so comparing the
    /// text puts `…:00.5Z` **before** `…:00Z` and the later instant would read as the earlier one.
    #[test]
    fn a_fraction_of_a_second_is_later_and_not_earlier() {
        assert!(
            "2020-01-01T00:00:00.5Z" < "2020-01-01T00:00:00Z",
            "the text comparison this test exists to avoid has changed"
        );
        let rule = evtx_rule("  oldest_record_time|gt: \"2020-01-01T00:00:00Z\"\n");
        let run = evtx_run(vec![evtx_observation(serde_json::json!({
            "oldest_record_time": "2020-01-01T00:00:00.5Z"
        }))]);
        assert!(found(&evaluate_rule(&rule, &[run])));
    }

    /// A timestamp an observation carries that is not one is not a match, and never a coercion.
    #[test]
    fn an_ordinal_comparison_of_two_kinds_is_not_a_match() {
        let rule = evtx_rule("  entries|gt: 1\n");
        let run = evtx_run(vec![evtx_observation(serde_json::json!({
            "entries": "many"
        }))]);
        assert!(not_found(&evaluate_rule(&rule, &[run])));
    }

    #[test]
    fn a_gap_reaches_a_rule_whose_condition_is_ordinal() {
        let rule = evtx_rule("  entries|gt: 1\n");
        assert!(unmeasured(&evaluate_rule(&rule, &[evtx_gap("entries")])));
    }

    #[test]
    fn the_text_operators_match_where_their_names_say() {
        for (block, matching, missing) in [
            (
                r"  path|startswith: 'C:\Windows\'",
                r"C:\Windows\System32\x.evtx",
                r"D:\Windows\x.evtx",
            ),
            ("  path|endswith: '.evtx'", r"C:\x.evtx", r"C:\x.evtx.bak"),
            (
                r"  path|contains: '\winevt\'",
                r"C:\Windows\System32\winevt\Logs\x.evtx",
                r"C:\Windows\x.evtx",
            ),
        ] {
            let rule = evtx_rule(&format!("{block}\n"));
            let run =
                |path: &str| evtx_run(vec![evtx_observation(serde_json::json!({ "path": path }))]);
            assert!(found(&evaluate_rule(&rule, &[run(matching)])), "{block}");
            assert!(not_found(&evaluate_rule(&rule, &[run(missing)])), "{block}");
        }
    }

    /// The string operators inherit ADR 0025: they fold ASCII case, and `cased` is the way back.
    #[test]
    fn a_text_operator_folds_case_unless_the_field_is_cased() {
        let folding = evtx_rule("  path|startswith: 'C:\\Windows\\'\n");
        let exact = evtx_rule("  path|startswith: 'C:\\Windows\\'\ncased: [path]\n");
        let run = || {
            evtx_run(vec![evtx_observation(serde_json::json!({
                "path": r"c:\WINDOWS\System32\winevt\Logs\Security.evtx"
            }))])
        };
        assert!(found(&evaluate_rule(&folding, &[run()])));
        assert!(not_found(&evaluate_rule(&exact, &[run()])));
    }

    /// `startswith` and `contains` are **text** operators: neither knows what a directory separator
    /// is, so a prefix that stops in the middle of a folder name matches a different folder. This
    /// test pins the behaviour ADR 0029 warns rule authors about rather than leaving it to be found
    /// by a rule that reads more broadly than its title.
    #[test]
    fn a_text_prefix_does_not_stop_at_a_directory_separator() {
        let rule = evtx_rule("  path|startswith: 'C:\\Users\\Public'\n");
        let run = evtx_run(vec![evtx_observation(serde_json::json!({
            "path": r"C:\Users\PublicRecords\x.evtx"
        }))]);
        assert!(found(&evaluate_rule(&rule, &[run])));
    }

    #[test]
    fn a_gap_reaches_a_rule_whose_condition_is_a_text_operator() {
        let rule = evtx_rule("  path|contains: 'winevt'\n");
        assert!(unmeasured(&evaluate_rule(&rule, &[evtx_gap("path")])));
    }

    /// `exists` asks about the field, not about its value: `null` is its own type and equality
    /// cannot stand in for either answer.
    #[test]
    fn exists_tells_a_field_that_is_there_from_one_that_is_not() {
        let present = evtx_rule("  oldest_record_time|exists: true\n");
        let absent = evtx_rule("  oldest_record_time|exists: false\n");
        let holds_records = evtx_run(vec![evtx_observation(serde_json::json!({
            "log": "Security", "oldest_record_time": "2026-09-13T10:00:00Z"
        }))]);
        let holds_none = evtx_run(vec![evtx_observation(
            serde_json::json!({ "log": "Security" }),
        )]);
        assert!(found(&evaluate_rule(
            &present,
            std::slice::from_ref(&holds_records)
        )));
        assert!(not_found(&evaluate_rule(
            &present,
            std::slice::from_ref(&holds_none)
        )));
        assert!(found(&evaluate_rule(&absent, &[holds_none])));
        assert!(not_found(&evaluate_rule(&absent, &[holds_records])));
    }

    #[test]
    fn a_gap_reaches_a_rule_asking_whether_a_field_exists() {
        let rule = evtx_rule("  oldest_record_time|exists: true\n");
        assert!(unmeasured(&evaluate_rule(
            &rule,
            &[evtx_gap("oldest_record_time")]
        )));
    }

    /// The one this whole change turns on. A field the collector could not read is not in the
    /// observation, and `exists: false` is satisfied by a field that is not in the observation — so
    /// without the gap being consulted **before** anything is matched, this rule would be `found`
    /// and the report would say "the log holds no record" about a log it could not read. That is the
    /// `unmeasured → not_found` collapse ADR 0002 exists to prevent, wearing a `found`.
    #[test]
    fn exists_false_on_an_unreadable_field_is_unmeasured_and_never_found() {
        let rule = evtx_rule("  oldest_record_time|exists: false\n");
        let run = CollectorRun::Measured {
            collector: "evtx".to_owned(),
            observations: vec![evtx_observation(serde_json::json!({ "log": "Security" }))],
            gaps: BTreeMap::from([(
                "oldest_record_time".to_owned(),
                UnmeasuredReason::AccessDenied,
            )]),
            discriminator_gaps: Vec::new(),
        };
        assert_eq!(
            evaluate_rule(&rule, &[run]).state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                expected: false
            }
        );
    }

    /// A gap in a field the rule does not read leaves `exists: false` alone: the early check is
    /// about the field the rule asks to be absent, not about every gap in the run.
    #[test]
    fn exists_false_is_unaffected_by_a_gap_in_another_field() {
        let rule = evtx_rule("  oldest_record_time|exists: false\n");
        let run = CollectorRun::Measured {
            collector: "evtx".to_owned(),
            observations: vec![evtx_observation(serde_json::json!({ "log": "Security" }))],
            gaps: BTreeMap::from([("provider".to_owned(), UnmeasuredReason::ReadFailed)]),
            discriminator_gaps: Vec::new(),
        };
        assert!(found(&evaluate_rule(&rule, &[run])));
    }

    /// Two conditions on one field, which is the reason the operator is a key suffix and not a list
    /// beside `match` the way `cased` is: a map keyed on the field name could hold only one of them.
    #[test]
    fn one_field_can_carry_two_conditions() {
        let rule = evtx_rule("  entries|gte: 2\n  entries|lt: 10\n");
        let run = |value: i64| {
            evtx_run(vec![evtx_observation(
                serde_json::json!({ "entries": value }),
            )])
        };
        assert!(found(&evaluate_rule(&rule, &[run(5)])));
        assert!(not_found(&evaluate_rule(&rule, &[run(1)])));
        assert!(not_found(&evaluate_rule(&rule, &[run(10)])));
    }

    /// `gaps` is keyed on the field name, and a suffixed key still resolves to it. ADR 0025 rejected
    /// a key suffix for `cased` on exactly this ground — that the key would stop equalling the field
    /// name and a field the collector could not read would report `not_found`. Splitting the key
    /// before the lookup is the answer, and this is what holds it.
    #[test]
    fn a_suffixed_key_is_still_found_in_gaps() {
        for block in [
            "  entries|gte: 2\n",
            "  path|contains: 'winevt'\n",
            "  path|exists: true\n",
        ] {
            let field = if block.contains("entries") {
                "entries"
            } else {
                "path"
            };
            let evidence = evaluate_rule(&evtx_rule(block), &[evtx_gap(field)]);
            assert!(unmeasured(&evidence), "{block}: {evidence:?}");
        }
    }

    /// A key whose suffix names no operator is refused by `rules::validate`, so it cannot be in a
    /// loaded bundle. If one ever arrived it must drop the observation rather than the condition:
    /// skipping the condition would widen the rule past what its title claims.
    #[test]
    fn a_key_with_an_unknown_operator_matches_nothing() {
        let rule = evtx_rule("  entries|atleast: 2\n");
        let run = evtx_run(vec![evtx_observation(serde_json::json!({ "entries": 5 }))]);
        assert!(not_found(&evaluate_rule(&rule, &[run])));
    }

    // ------------------------------------------------------------------------------------------
    // ADR 0044: a gap confined to one value of a collector's discriminator. The shapes are
    // `fivem_dir`'s — `location` names the place — because that is the collector that emits them.
    // ------------------------------------------------------------------------------------------

    /// A `fivem_dir` rule carrying the `match` block given.
    fn fivem_rule(match_block: &str) -> Rule {
        let yaml = format!(
            "id: 6e1d2c3b-4a59-4687-9b0c-1d2e3f405162\ntitle: t\ndescription: d\nstatus: experimental\ncollector: fivem_dir\nstrength: presence\nmatch:\n{match_block}retention: The files in the folder when the scan ran.\nfalsepositives: [x]\nauthor: a\ndate: 2026-09-14\n"
        );
        serde_saphyr::from_str(&yaml).expect("the test rule parses")
    }

    fn fivem_observation(fields: serde_json::Value) -> Observation {
        Observation {
            collector: "fivem_dir".to_owned(),
            fields: serde_json::from_value(fields).expect("the test fields are an object"),
        }
    }

    /// Every field of the collector a gap, with `reason`, for the observations at `location` only.
    fn unreadable(location: &str, reason: UnmeasuredReason) -> DiscriminatorGaps {
        DiscriminatorGaps {
            discriminator: "location".to_owned(),
            value: serde_json::Value::from(location),
            gaps: ["files", "folder", "location", "path", "sha256", "signature"]
                .into_iter()
                .map(|field| (field.to_owned(), reason))
                .collect(),
        }
    }

    fn fivem_run(observations: Vec<Observation>, places: Vec<DiscriminatorGaps>) -> CollectorRun {
        CollectorRun::Measured {
            collector: "fivem_dir".to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps: places,
        }
    }

    /// The plugins folder was listed and holds one file with the signature answer given; Enhanced's
    /// program folder, where its `FiveM.exe` would be, could not be listed.
    fn plugins_read_enhanced_exe_denied(signature: &str) -> CollectorRun {
        fivem_run(
            vec![
                fivem_observation(
                    serde_json::json!({ "location": "plugins", "folder": "listed", "files": 1 }),
                ),
                fivem_observation(serde_json::json!({
                    "location": "plugins",
                    "path": r"C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.app\plugins\x.dll",
                    "signature": signature,
                })),
            ],
            vec![unreadable("enhanced_exe", UnmeasuredReason::AccessDenied)],
        )
    }

    const PLUGINS_NOT_VERIFIED: &str = "  location: plugins\n  signature: [no_embedded_signature, invalid, unverifiable_offline]\n";

    /// The defect ADR 0036 recorded. A place this rule's `match` rules out could not be read, and the
    /// place it asks about was: the answer is what that place holds, found or not found.
    #[test]
    fn a_rule_for_a_place_that_was_read_keeps_its_answer_when_another_place_was_not() {
        let rule = fivem_rule(PLUGINS_NOT_VERIFIED);
        let fired = evaluate_rule(&rule, &[plugins_read_enhanced_exe_denied("invalid")]);
        assert!(found(&fired), "{fired:?}");
        let quiet = evaluate_rule(&rule, &[plugins_read_enhanced_exe_denied("valid")]);
        assert!(not_found(&quiet), "{quiet:?}");
    }

    /// The other half: a rule for the place nobody could read is `unmeasured` with that place's
    /// reason, never `not_found`. A value list reaches the place when any of its values is it, and the
    /// ASCII fold `match` applies reaches the discriminator too.
    #[test]
    fn a_rule_for_the_place_that_was_not_read_is_unmeasured() {
        for block in [
            "  location: enhanced_exe\n  signature: valid\n",
            "  location: [legacy_exe, enhanced_exe]\n  signature: [no_embedded_signature, invalid, unverifiable_offline]\n",
            "  location: ENHANCED_EXE\n  signature: valid\n",
        ] {
            let evidence = evaluate_rule(
                &fivem_rule(block),
                &[plugins_read_enhanced_exe_denied("valid")],
            );
            assert_eq!(
                evidence.state,
                EvidenceState::Unmeasured {
                    reason: UnmeasuredReason::AccessDenied,
                    expected: false
                },
                "{block}"
            );
        }
    }

    /// `cased` on the discriminator is honoured when deciding which places a rule reaches, exactly as
    /// it is when matching: a byte comparison that no observation there could satisfy rules it out.
    #[test]
    fn a_cased_discriminator_condition_reaches_only_the_spelling_it_names() {
        let rule = fivem_rule("  location: ENHANCED_EXE\n  signature: valid\ncased: [location]\n");
        let evidence = evaluate_rule(&rule, &[plugins_read_enhanced_exe_denied("valid")]);
        assert!(not_found(&evidence), "{evidence:?}");
    }

    /// A rule that names no place could match in any of them, so the unread one reaches it — and what
    /// it matched where the collector could read is still `found`.
    #[test]
    fn a_rule_without_a_condition_on_the_discriminator_is_reached_by_every_place() {
        let rule = fivem_rule("  signature: invalid\n");
        let evidence = evaluate_rule(&rule, &[plugins_read_enhanced_exe_denied("valid")]);
        assert!(unmeasured(&evidence), "{evidence:?}");
        let evidence = evaluate_rule(&rule, &[plugins_read_enhanced_exe_denied("invalid")]);
        assert!(found(&evidence), "{evidence:?}");
    }

    /// Two places unreadable and one read. Each rule is reached by the unread places its `match`
    /// allows, and the first of those in the run's order gives the reason — the order is the
    /// collector's ranking. A rule for the place that was read is still answered.
    #[test]
    fn both_places_a_rule_names_unreadable_is_unmeasured() {
        let run = || {
            fivem_run(
                vec![fivem_observation(
                    serde_json::json!({ "location": "plugins", "folder": "listed", "files": 0 }),
                )],
                vec![
                    unreadable("enhanced_exe", UnmeasuredReason::AccessDenied),
                    unreadable("legacy_exe", UnmeasuredReason::ReadFailed),
                ],
            )
        };
        let client = fivem_rule(
            "  location: [legacy_exe, enhanced_exe]\n  signature: [no_embedded_signature, invalid, unverifiable_offline]\n",
        );
        assert_eq!(
            evaluate_rule(&client, &[run()]).state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                expected: false
            }
        );
        let legacy = fivem_rule("  location: legacy_exe\n  signature: valid\n");
        assert_eq!(
            evaluate_rule(&legacy, &[run()]).state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::ReadFailed,
                expected: false
            }
        );
        assert!(not_found(&evaluate_rule(
            &fivem_rule(PLUGINS_NOT_VERIFIED),
            &[run()]
        )));
    }

    /// ADR 0029's guarantee, confined to a place. The rule asks for a file whose signature is absent.
    ///
    /// - Nothing matched anywhere and a place was not read: `unmeasured`, not `not_found`.
    /// - An observation **from the unreadable place** that lacks `signature` is not a match: its
    ///   signature may be missing because nobody read it. Without that it would be `found`.
    /// - A file from a place that was read and genuinely carries no signature is `found`, which a
    ///   run-wide gap would have hidden.
    #[test]
    fn exists_false_is_never_satisfied_by_an_observation_from_a_place_that_was_not_read() {
        let rule = fivem_rule("  path|exists: true\n  signature|exists: false\n");

        let nothing = evaluate_rule(&rule, &[plugins_read_enhanced_exe_denied("valid")]);
        assert!(unmeasured(&nothing), "{nothing:?}");

        let from_the_unread_place = fivem_run(
            vec![fivem_observation(serde_json::json!({
                "location": "enhanced_exe",
                "path": r"C:\Users\fixtureuser\AppData\Local\FiveM for GTAV Enhanced\FiveM.exe",
            }))],
            vec![unreadable("enhanced_exe", UnmeasuredReason::AccessDenied)],
        );
        assert_eq!(
            evaluate_rule(&rule, &[from_the_unread_place]).state,
            EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                expected: false
            }
        );

        let from_a_read_place = fivem_run(
            vec![fivem_observation(serde_json::json!({
                "location": "plugins",
                "path": r"C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.app\plugins\locked.dll",
            }))],
            vec![unreadable("enhanced_exe", UnmeasuredReason::AccessDenied)],
        );
        let evidence = evaluate_rule(&rule, &[from_a_read_place]);
        assert!(found(&evidence), "{evidence:?}");
    }

    /// A place's gaps reach only the fields they list: a rule whose fields that place did read is not
    /// made `unmeasured` by it.
    #[test]
    fn a_place_whose_gaps_do_not_name_the_rules_fields_leaves_it_alone() {
        let place = DiscriminatorGaps {
            discriminator: "location".to_owned(),
            value: serde_json::Value::from("enhanced_exe"),
            gaps: BTreeMap::from([("sha256".to_owned(), UnmeasuredReason::ReadFailed)]),
        };
        let evidence = evaluate_rule(
            &fivem_rule("  signature: invalid\n"),
            &[fivem_run(vec![], vec![place])],
        );
        assert!(not_found(&evidence), "{evidence:?}");
    }

    /// An observation a place's gaps kept from matching by absence is not dropped between the rule and
    /// the report: no rule matched it, so it is an unmatched observation (ADR 0014).
    #[test]
    fn an_observation_kept_from_matching_by_a_place_gap_is_unmatched() {
        let yaml = "id: 6e1d2c3b-4a59-4687-9b0c-1d2e3f405162\ntitle: t\ndescription: d\nstatus: experimental\ncollector: fivem_dir\nstrength: context\nmatch:\n  path|exists: true\n  signature|exists: false\nretention: r\nfalsepositives: [x]\nauthor: a\ndate: 2026-09-14\n";
        let json = serde_json::json!({
            "rules": [{ "path": "fivem_dir/signatures/rule-0/rule.yaml", "yaml": yaml }],
            "i18n": []
        })
        .to_string();
        let bundle = Bundle::from_bundle_json(&json).unwrap();
        let seen = fivem_observation(serde_json::json!({
            "location": "enhanced_exe",
            "path": r"C:\Users\fixtureuser\AppData\Local\FiveM for GTAV Enhanced\FiveM.exe",
        }));
        let report = evaluate(
            &bundle,
            &[fivem_run(
                vec![seen.clone()],
                vec![unreadable("enhanced_exe", UnmeasuredReason::AccessDenied)],
            )],
            header(),
            &SelfIdentity::default(),
        );
        assert!(unmeasured(&report.evidence[0]), "{:?}", report.evidence);
        assert_eq!(
            report.unmatched,
            vec![UnmatchedGroup {
                collector: "fivem_dir".to_owned(),
                observations: vec![seen],
            }]
        );
    }
}
