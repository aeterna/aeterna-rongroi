// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask check-rules`: the bundle validation plus fixtures (docs/rules-authoring.md).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::bail;
use rongroi_collectors::FieldKind;
use rongroi_core::bundle::{Bundle, BundleError};
use rongroi_core::engine;
use rongroi_core::model::{CollectorRun, EvidenceState, Observation, UnmeasuredReason};
use rongroi_core::rules::{MatchKey, Operator, Rule};
use rongroi_core::source_tree::collect_bundle_json;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    #[serde(rename = "description")]
    _description: Option<String>,
    observations: Vec<Observation>,
    #[serde(default)]
    gaps: BTreeMap<String, UnmeasuredReason>,
    #[serde(default)]
    expect_matches: Option<usize>,
}

/// Everything `run` needs to print or bail on, computed without touching stdout/stderr so tests
/// can assert on the exact problem text instead of only on pass/fail.
struct CheckRulesOutcome {
    problems: Vec<String>,
    rule_count: usize,
    fixture_count: usize,
    language_count: usize,
}

pub fn run(root: &Path) -> anyhow::Result<()> {
    let outcome = check(root)?;
    if outcome.problems.is_empty() {
        println!(
            "check-rules: {} rule(s), {} fixture(s), {} language(s) ok",
            outcome.rule_count, outcome.fixture_count, outcome.language_count
        );
        Ok(())
    } else {
        for problem in &outcome.problems {
            eprintln!("error: {problem}");
        }
        bail!("check-rules: {} problem(s)", outcome.problems.len())
    }
}

fn check(root: &Path) -> anyhow::Result<CheckRulesOutcome> {
    let rules_dir = root.join("rules");
    let json = collect_bundle_json(&rules_dir)?;
    let bundle = match Bundle::from_bundle_json(&json) {
        Ok(bundle) => bundle,
        Err(BundleError::Invalid(problems)) => {
            return Ok(CheckRulesOutcome {
                problems: problems.iter().map(ToString::to_string).collect(),
                rule_count: 0,
                fixture_count: 0,
                language_count: 0,
            });
        }
        Err(error) => bail!("check-rules: {error}"),
    };

    let vocabulary = Vocabulary::of_this_build();
    let mut problems = Vec::new();
    // No clock: the dates are validated here and compared with today only by the scheduled
    // `check-pin-expiry`, so a pull request is never red because of the calendar.
    let pins = crate::certificate_pins::read(root, &mut problems)?;
    crate::certificate_pins::check_against_bundle(&pins, &bundle, &mut problems);
    let mut fixture_count = 0;
    for sourced in bundle.rules() {
        vocabulary.check(&sourced.path, &sourced.rule, &mut problems);
        let rule_folder = rules_dir.join(sourced.path.trim_end_matches("rule.yaml"));
        let tests_dir = rule_folder.join("tests");
        let positive = json_files(&tests_dir.join("positive"))?;
        let negative = json_files(&tests_dir.join("negative"))?;

        // Every rule links to `tests/` from the report, `experimental` ones included (ADR 0045), and
        // git keeps no empty folder — so a rule missing this one can never have been given even one
        // fixture. `status.needs_fixtures()` below asks a stricter question (a positive *and* a
        // negative fixture) that only `test` and `stable` must answer; this one is unconditional.
        if !tests_dir.is_dir() {
            problems.push(format!(
                "rules/{}: every rule needs a tests/ folder with at least one fixture file; the report links to it (ADR 0045)",
                sourced.path
            ));
        }

        if sourced.rule.status.needs_fixtures() {
            if positive.is_empty() {
                problems.push(format!(
                    "rules/{}: status `{:?}` needs a positive fixture in tests/positive/",
                    sourced.path, sourced.rule.status
                ));
            }
            if negative.is_empty() {
                problems.push(format!(
                    "rules/{}: status `{:?}` needs a negative fixture in tests/negative/",
                    sourced.path, sourced.rule.status
                ));
            }
        }

        if tests_dir.is_dir() {
            for entry in std::fs::read_dir(&tests_dir)? {
                let name = entry?.file_name();
                if name != "positive" && name != "negative" {
                    problems.push(format!(
                        "{}: only `positive/` and `negative/` belong in tests/",
                        crate::display(root, &tests_dir.join(name))
                    ));
                }
            }
        }

        let cases = positive
            .iter()
            .map(|file| (file, true))
            .chain(negative.iter().map(|file| (file, false)));
        for (file, expect_found) in cases {
            fixture_count += 1;
            if let Err(message) = check_fixture(&sourced.rule, file, expect_found) {
                problems.push(format!("{}: {message}", crate::display(root, file)));
            }
        }
    }

    Ok(CheckRulesOutcome {
        problems,
        rule_count: bundle.rules().len(),
        fixture_count,
        language_count: bundle.languages().len(),
    })
}

/// What the collectors in this build can be asked about: each collector's id, and the field names it
/// declares it can emit (`rongroi_collectors::Collector::fields`).
///
/// Built from `rongroi_collectors::all()`, which is the list `scan::run` iterates, so the vocabulary
/// this gate enforces is the one the shipped executable actually has — the same argument ADR 0017
/// made for `check-baseline` running the product's own pipeline. ADR 0026 has the reasoning and the
/// alternative that was rejected.
struct Vocabulary {
    fields: BTreeMap<&'static str, BTreeMap<&'static str, FieldKind>>,
    reasons: BTreeMap<&'static str, BTreeSet<&'static str>>,
}

/// The one unmeasured reason no collector declares: the engine produces it when the build has no
/// run for the rule's collector at all (`engine::evaluate_rule`), so any rule may expect it.
const ENGINE_REASON: UnmeasuredReason = UnmeasuredReason::CollectorUnavailable;

impl Vocabulary {
    fn of_this_build() -> Self {
        let collectors = rongroi_collectors::all();
        Self {
            fields: collectors
                .iter()
                .map(|collector| {
                    let fields = collector
                        .fields()
                        .iter()
                        .map(|field| (field.name, field.kind))
                        .collect();
                    (collector.id(), fields)
                })
                .collect(),
            reasons: collectors
                .iter()
                .map(|collector| {
                    let reasons = collector
                        .unmeasured_reasons()
                        .iter()
                        .map(|reason| reason.as_str())
                        .chain(std::iter::once(ENGINE_REASON.as_str()))
                        .collect();
                    (collector.id(), reasons)
                })
                .collect(),
        }
    }

    /// Rejects a rule that names a collector this build does not have, or a field that collector
    /// cannot emit.
    ///
    /// Either mistake produces a rule that is never `Found` on any machine — an unknown collector is
    /// `Unmeasured { collector_unavailable }`, an unknown field is a `match` key no observation
    /// carries and therefore `NotFound` — and `NotFound` is shown to a player as "this was looked
    /// for and was not there". Neither is visible in the rule file, in `check-baseline`, or in a
    /// fixture written from the same misspelling.
    fn check(&self, path: &str, rule: &Rule, problems: &mut Vec<String>) {
        let Some(known) = self.fields.get(rule.collector.as_str()) else {
            problems.push(format!(
                "rules/{path}: no collector in this build has the id `{}`; this build has {}",
                rule.collector,
                comma(self.fields.keys().copied())
            ));
            // One mistake, one message: with no collector resolved there is nothing to check the
            // `match` field names against, and reporting each of them would name the same defect
            // once per field.
            return;
        };
        for (key, value) in rule.conditions() {
            let field = key.field();
            let Some(kind) = known.get(field).copied() else {
                let suggestion = nearest(field, known)
                    .map_or_else(String::new, |name| format!(" (did you mean `{name}`?)"));
                problems.push(format!(
                    "rules/{path}: `match` names `{field}`, which the `{}` collector cannot emit{suggestion}; it emits {}",
                    rule.collector,
                    comma(known.keys().copied())
                ));
                continue;
            };
            // An unknown operator is `rules::validate`'s to report, and it already has.
            if let MatchKey::Known { operator, .. } = key {
                check_operator(
                    path,
                    &rule.collector,
                    field,
                    operator,
                    kind,
                    value,
                    problems,
                );
            }
        }
        self.check_unmeasured_when(path, rule, problems);
    }

    /// Rejects an `unmeasured_when` entry naming a reason this rule can never be given, and one
    /// naming a reason no rule may declare at all.
    ///
    /// Since ADR 0027 the field decides what an SS view lists: a declared reason is counted, an
    /// undeclared one is listed. A reason the rule's collector cannot produce is therefore a
    /// suppression that never fires — the author believes they have said "this one is ordinary
    /// here" and the report will list it anyway — and nothing in the rule file, in `check-baseline`
    /// or in a fixture shows it. Since ADR 0030 every one of the twelve reasons has a producer in
    /// some collector, so that half of the check is now entirely about which collector:
    /// `not_on_this_os` is `pca` and nothing else, `service_disabled` is `prefetch` and nothing
    /// else, and `budget_spent` is `evtx` and nothing else.
    ///
    /// The other half is the mirror image: a reason [`UnmeasuredReason::is_always_listed`] answers
    /// true for is one a view lists whatever the rule said, so declaring it is a suppression that
    /// never fires for the opposite reason — not because the reason cannot arrive, but because the
    /// declaration is ignored when it does (ADR 0032). Left unchecked it reads, in the rule file, as
    /// a decision an author made; every one of these rules carried such a line for `read_failed`
    /// from before anything read the field.
    fn check_unmeasured_when(&self, path: &str, rule: &Rule, problems: &mut Vec<String>) {
        let Some(known) = self.reasons.get(rule.collector.as_str()) else {
            return;
        };
        let mut seen = BTreeSet::new();
        for reason in &rule.unmeasured_when {
            let name = reason.as_str();
            if !seen.insert(name) {
                problems.push(format!(
                    "rules/{path}: `unmeasured_when` names `{name}` twice"
                ));
                continue;
            }
            if reason.is_always_listed() {
                problems.push(format!(
                    "rules/{path}: `unmeasured_when` names `{name}`, which no rule may declare; a view lists it whatever the rule says, because it names a read that did not finish rather than a kind of machine"
                ));
                continue;
            }
            if !known.contains(name) {
                problems.push(format!(
                    "rules/{path}: `unmeasured_when` names `{name}`, which the `{}` collector cannot report; it reports {}",
                    rule.collector,
                    comma(known.iter().copied())
                ));
            }
        }
    }
}

/// Rejects an operator the field's declared kind cannot take, and a value of a shape that kind
/// cannot hold.
///
/// `rules::validate` has already checked the value against the **operator** — that `exists` gets a
/// boolean, that an ordinal comparison gets a number or a timestamp. What only this build knows is
/// what the field itself holds, so this is where `name|gt: 3` is caught: text has no order, the
/// comparison can never be true, and the rule would be `not_found` on every machine — which this
/// program shows a player as evidence that something was looked for and was not there. That is the
/// defect ADR 0026 removed for field names, and this is the same defect through the operator.
fn check_operator(
    path: &str,
    collector: &str,
    field: &str,
    operator: Operator,
    kind: FieldKind,
    value: &serde_json::Value,
    problems: &mut Vec<String>,
) {
    let key = operator
        .as_str()
        .map_or_else(|| field.to_owned(), |name| format!("{field}|{name}"));
    if operator.is_ordinal() {
        match kind {
            FieldKind::Number if !holds(value, serde_json::Value::is_number) => problems.push(format!(
                "rules/{path}: `match` key `{key}` puts values in order, and the `{collector}` collector emits `{field}` as a number, so the value must be a number too"
            )),
            FieldKind::Timestamp if !holds(value, serde_json::Value::is_string) => problems.push(format!(
                "rules/{path}: `match` key `{key}` puts values in order, and the `{collector}` collector emits `{field}` as a timestamp, so the value must be an RFC 3339 timestamp such as `2026-09-13T00:00:00Z`"
            )),
            FieldKind::Number | FieldKind::Timestamp => {}
            FieldKind::Text | FieldKind::Bool => problems.push(format!(
                "rules/{path}: `match` key `{key}` puts values in order, which the `{collector}` collector's `{field}` cannot be: it emits {}. `gt`, `gte`, `lt` and `lte` need a number or a timestamp",
                kind.as_str()
            )),
        }
        return;
    }
    if matches!(
        operator,
        Operator::StartsWith | Operator::EndsWith | Operator::Contains
    ) && kind != FieldKind::Text
    {
        problems.push(format!(
            "rules/{path}: `match` key `{key}` matches text, which the `{collector}` collector's `{field}` is not: it emits {}",
            kind.as_str()
        ));
    }
}

/// Whether a `match` value, or every element of a list value, has the shape `is` accepts.
fn holds(value: &serde_json::Value, is: fn(&serde_json::Value) -> bool) -> bool {
    value
        .as_array()
        .map_or_else(|| is(value), |list| list.iter().all(is))
}

/// The declared name closest to `field`, when one is close enough to be a misspelling of it rather
/// than a different name. Two edits is the widest gap that is still more likely a typo than a choice.
fn nearest<'a>(field: &str, known: &BTreeMap<&'a str, FieldKind>) -> Option<&'a str> {
    known
        .keys()
        .map(|name| (distance(field, name), *name))
        .filter(|(distance, _)| *distance <= 2)
        .min_by_key(|(distance, name)| (*distance, *name))
        .map(|(_, name)| name)
}

/// Levenshtein distance, one row at a time. Field names are short, so the quadratic cost is bounded
/// by the length of the longest name a collector declares.
fn distance(left: &str, right: &str) -> usize {
    let right: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (row, left_char) in left.chars().enumerate() {
        current[0] = row + 1;
        for (column, right_char) in right.iter().enumerate() {
            let substitution = usize::from(left_char != *right_char);
            current[column + 1] = (previous[column] + substitution)
                .min(previous[column + 1] + 1)
                .min(current[column] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

fn comma<'a>(names: impl Iterator<Item = &'a str>) -> String {
    names.collect::<Vec<_>>().join(", ")
}

fn json_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn check_fixture(rule: &Rule, file: &Path, expect_found: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("cannot read: {e}"))?;
    let fixture: Fixture =
        serde_json::from_str(&text).map_err(|e| format!("invalid fixture JSON: {e}"))?;
    let run = CollectorRun::Measured {
        collector: rule.collector.clone(),
        observations: fixture.observations,
        gaps: fixture.gaps,
        discriminator_gaps: Vec::new(),
    };
    let evidence = engine::evaluate_rule(rule, &[run]);
    match (&evidence.state, expect_found) {
        (EvidenceState::Found { observations }, true) => match fixture.expect_matches {
            Some(expected) if expected != observations.len() => Err(format!(
                "expected {expected} matching observation(s), got {}",
                observations.len()
            )),
            _ => Ok(()),
        },
        (EvidenceState::NotFound { .. }, false) => Ok(()),
        (state, true) => Err(format!(
            "positive fixture must make the rule `found`, got `{}`",
            state_name(state)
        )),
        (state, false) => Err(format!(
            "negative fixture must make the rule `not_found`, got `{}`",
            state_name(state)
        )),
    }
}

fn state_name(state: &EvidenceState) -> &'static str {
    match state {
        EvidenceState::Found { .. } => "found",
        EvidenceState::NotFound { .. } => "not_found",
        EvidenceState::Unmeasured { .. } => "unmeasured",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// A directory under the OS temp dir, unique per test, deleted on drop (even on panic) so a
    /// failed assertion never leaves a fixture tree behind.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the epoch")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "aeterna-rongroi-xtask-check-rules-{}-{label}-{n}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp root");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().expect("path has a parent")).expect("create parent dirs");
        fs::write(path, contents).expect("write fixture file");
    }

    /// A rule directory's `tests/` folder, present but holding nothing. Used by tests whose fixture
    /// content is beside the point, so the unconditional "every rule needs a tests/ folder" check
    /// (ADR 0045) does not add a second, unrelated problem to their assertions. Git itself never keeps
    /// a folder this empty; only this in-process temp tree can.
    fn write_empty_tests_dir(rule_dir: &Path) {
        fs::create_dir_all(rule_dir.join("tests")).expect("create empty tests dir");
    }

    /// Modelled on the real `rules/posture/boot/secure-boot-disabled/rule.yaml`.
    const VALID_RULE: &str = "id: 7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7
title: Secure Boot is turned off
description: Windows reports that UEFI Secure Boot is off.
status: test
collector: posture
strength: posture
match:
  secure_boot: disabled
retention: Current setting only.
falsepositives:
  - PCs that boot in legacy BIOS or CSM mode
author: aeterna-rongroi contributors
date: 2026-09-11
";

    const POSITIVE_FIXTURE: &str = r#"{
  "observations": [
    { "collector": "posture", "fields": { "secure_boot": "disabled" } }
  ],
  "expect_matches": 1
}
"#;

    const NEGATIVE_FIXTURE: &str = r#"{
  "observations": [
    { "collector": "posture", "fields": { "secure_boot": "enabled" } }
  ]
}
"#;

    fn write_valid_rule(root: &Path, slug: &str) {
        let dir = root.join("rules/posture/boot").join(slug);
        write(&dir.join("rule.yaml"), VALID_RULE);
        write(&dir.join("tests/positive/on.json"), POSITIVE_FIXTURE);
        write(&dir.join("tests/negative/off.json"), NEGATIVE_FIXTURE);
    }

    #[test]
    fn valid_rule_tree_passes() {
        let tmp = TempRoot::new("valid");
        write_valid_rule(tmp.path(), "secure-boot-disabled");

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);
        assert_eq!(outcome.rule_count, 1);
        assert_eq!(outcome.fixture_count, 2);
    }

    /// An `allow` entry naming a certificate needs a row in `rules/certificate-pins.csv`, and the row
    /// needs the entry: otherwise the certificate's expiry is watched by nothing, or a date warns
    /// about a certificate no rule allows (ADR 0036).
    #[test]
    fn a_certificate_allow_entry_and_its_pin_row_go_together() {
        let cert = "b".repeat(64);
        let tmp = TempRoot::new("pins");
        let dir = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        write(
            &dir.join("rule.yaml"),
            &format!("{VALID_RULE}allow:\n  - signer_cert_sha256: {cert}\n"),
        );
        write(&dir.join("tests/positive/on.json"), POSITIVE_FIXTURE);
        write(&dir.join("tests/negative/off.json"), NEGATIVE_FIXTURE);

        let outcome = check(tmp.path()).expect("check-rules should run to completion");
        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains("has no row in `rules/certificate-pins.csv`"),
            "{:?}",
            outcome.problems
        );

        let header = "rule_id,signer_cert_sha256,subject,not_before,not_after,measured_on";
        let row = |id: &str| {
            format!("{id},{cert},CN=Example,2026-07-21T00:00:00Z,2027-09-05T23:59:59Z,2026-09-13\n")
        };
        write(
            &tmp.path().join("rules/certificate-pins.csv"),
            &format!("{header}\n{}", row("7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7")),
        );
        let outcome = check(tmp.path()).expect("check-rules should run to completion");
        assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);

        write(
            &tmp.path().join("rules/certificate-pins.csv"),
            &format!(
                "{header}\n{}{}",
                row("7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7"),
                row("00000000-0000-4000-8000-000000000000")
            ),
        );
        let outcome = check(tmp.path()).expect("check-rules should run to completion");
        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains("watches nothing"),
            "{:?}",
            outcome.problems
        );
    }

    /// Gate (1): two rules sharing the same `id` must be rejected.
    #[test]
    fn duplicate_rule_id_is_rejected() {
        let tmp = TempRoot::new("dup-id");
        // `experimental` does not need fixtures, so with a tests/ folder present the only expected
        // problem is the duplicate id.
        let rule = VALID_RULE.replace("status: test", "status: experimental");
        let first = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        let second = tmp
            .path()
            .join("rules/posture/boot/secure-boot-disabled-copy");
        write(&first.join("rule.yaml"), &rule);
        write(&second.join("rule.yaml"), &rule);
        write_empty_tests_dir(&first);
        write_empty_tests_dir(&second);

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(
                "id `7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7` is used by more than one rule"
            ),
            "{:?}",
            outcome.problems
        );
    }

    /// An `experimental` rule needs no positive or negative fixture, but it still needs the `tests/`
    /// folder itself: the report links to it for every rule (ADR 0045), and git keeps no folder this
    /// empty, so a rule missing it can never have even one fixture committed for it.
    #[test]
    fn an_experimental_rule_without_a_tests_folder_is_rejected() {
        let tmp = TempRoot::new("no-tests-folder");
        let rule = VALID_RULE.replace("status: test", "status: experimental");
        let dir = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        write(&dir.join("rule.yaml"), &rule);
        // No `tests/` folder at all — not even an empty one.

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(
                "rules/posture/boot/secure-boot-disabled/rule.yaml: every rule needs a tests/ folder with at least one fixture file; the report links to it (ADR 0045)"
            ),
            "{:?}",
            outcome.problems
        );
    }

    /// The mirror of the rejection above: once the `tests/` folder exists — even empty, which git
    /// cannot actually keep, but which is enough for this gate — an `experimental` rule passes without
    /// a positive or negative fixture. `status: test` and `stable` are the ones that need more, in
    /// `status_test_without_negative_fixture_is_rejected` below.
    #[test]
    fn an_experimental_rule_with_only_an_empty_tests_folder_passes() {
        let tmp = TempRoot::new("empty-tests-folder");
        let rule = VALID_RULE.replace("status: test", "status: experimental");
        let dir = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        write(&dir.join("rule.yaml"), &rule);
        write_empty_tests_dir(&dir);

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);
    }

    /// Gate (2): a `status: test` rule with no negative fixture must be rejected.
    #[test]
    fn status_test_without_negative_fixture_is_rejected() {
        let tmp = TempRoot::new("missing-negative");
        let dir = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        write(&dir.join("rule.yaml"), VALID_RULE);
        write(&dir.join("tests/positive/on.json"), POSITIVE_FIXTURE);
        // No tests/negative/ directory at all.

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(
                "rules/posture/boot/secure-boot-disabled/rule.yaml: status `Test` needs a negative fixture in tests/negative/"
            ),
            "{:?}",
            outcome.problems
        );
    }

    /// Gate (4): a rule whose `collector` is not a collector in this build must be rejected.
    ///
    /// Before ADR 0026 such a rule parsed, passed every gate, and evaluated to
    /// `Unmeasured { collector_unavailable }` on every machine — silently, because `check-baseline`
    /// only fails on `Found`.
    #[test]
    fn a_rule_naming_a_collector_this_build_does_not_have_is_rejected() {
        let tmp = TempRoot::new("unknown-collector");
        // `experimental` needs no fixtures, so with a tests/ folder present the collector id is the
        // only expected problem.
        let rule = VALID_RULE
            .replace("status: test", "status: experimental")
            .replace("collector: posture", "collector: postures");
        let dir = tmp.path().join("rules/postures/boot/secure-boot-disabled");
        write(&dir.join("rule.yaml"), &rule);
        write_empty_tests_dir(&dir);

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(
                "rules/postures/boot/secure-boot-disabled/rule.yaml: no collector in this build has the id `postures`"
            ),
            "{:?}",
            outcome.problems
        );
        // The message names what this build does have, so the fix does not need a grep.
        assert!(
            outcome.problems[0].contains("posture"),
            "{:?}",
            outcome.problems
        );
    }

    /// Gate (5): a `match` field the named collector cannot emit must be rejected.
    ///
    /// This is the misspelling that used to ship as a rule that is `not_found` on every machine —
    /// which this program presents to a player as evidence that something was looked for and was not
    /// there.
    #[test]
    fn a_match_field_the_collector_cannot_emit_is_rejected() {
        let tmp = TempRoot::new("unknown-field");
        let rule = VALID_RULE
            .replace("status: test", "status: experimental")
            .replace("  secure_boot: disabled", "  secure_boo: disabled");
        let dir = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        write(&dir.join("rule.yaml"), &rule);
        write_empty_tests_dir(&dir);

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(
                "`match` names `secure_boo`, which the `posture` collector cannot emit (did you mean `secure_boot`?)"
            ),
            "{:?}",
            outcome.problems
        );
    }

    /// A field name that is nothing like any of them gets the vocabulary and no guess: a wrong
    /// suggestion is worse than none, because it reads as though the tool knows what was meant.
    #[test]
    fn an_unrelated_match_field_is_rejected_without_a_suggestion() {
        let tmp = TempRoot::new("unrelated-field");
        let rule = VALID_RULE
            .replace("status: test", "status: experimental")
            .replace("  secure_boot: disabled", "  wallpaper: blue");
        let dir = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        write(&dir.join("rule.yaml"), &rule);
        write_empty_tests_dir(&dir);

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            !outcome.problems[0].contains("did you mean"),
            "{:?}",
            outcome.problems
        );
        assert!(
            outcome.problems[0]
                .contains("it emits hvci, script_block_logging, script_block_logging_pwsh, script_block_logging_pwsh_user, script_block_logging_user, secure_boot, secure_boot_firmware, test_signing, tpm, tpm_spec_version"),
            "{:?}",
            outcome.problems
        );
    }

    /// Every collector in the build is asked for its vocabulary, so a rule for any of them can be
    /// written. A `check` that resolved only the collectors a rule already uses would pass this test
    /// and reject the first rule written for a new collector.
    #[test]
    fn every_collector_in_the_build_has_a_vocabulary() {
        let vocabulary = Vocabulary::of_this_build();

        for collector in rongroi_collectors::all() {
            let fields = vocabulary
                .fields
                .get(collector.id())
                .unwrap_or_else(|| panic!("collector `{}` has no vocabulary", collector.id()));
            assert!(
                !fields.is_empty(),
                "collector `{}` declares no field, so no rule could ever be written for it",
                collector.id()
            );
        }
    }

    /// A reason its own collector does not produce is a suppression that never fires: the author has
    /// written "this one is ordinary on some machines" and the report lists it anyway. `posture`
    /// reads registry values and a platform API and has no service to be switched off, so
    /// `service_disabled` — which since ADR 0030 `prefetch` does produce — is still wrong here.
    #[test]
    fn an_unmeasured_when_reason_this_build_cannot_produce_is_rejected() {
        let tmp = TempRoot::new("dead-reason");
        let rule = VALID_RULE
            .replace("status: test", "status: experimental")
            .replace(
                "retention: Current setting only.",
                "retention: Current setting only.\nunmeasured_when: [service_disabled]",
            );
        let dir = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        write(&dir.join("rule.yaml"), &rule);
        write_empty_tests_dir(&dir);

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(
                "`unmeasured_when` names `service_disabled`, which the `posture` collector cannot report"
            ),
            "{:?}",
            outcome.problems
        );
        // The message names what it can report, so the fix does not need a grep.
        assert!(
            outcome.problems[0]
                .contains("it reports access_denied, collector_unavailable, not_admin, not_windows, read_failed, source_absent"),
            "{:?}",
            outcome.problems
        );
    }

    /// A reason another collector produces is still wrong here: `posture` reads settings, not a
    /// place records are kept, so it cannot report `source_empty` — which `bam` and `pca` do. Until
    /// ADR 0038 this test used `not_admin`, which `posture` now reports for the firmware reading.
    #[test]
    fn an_unmeasured_when_reason_another_collector_produces_is_rejected() {
        let tmp = TempRoot::new("wrong-collector-reason");
        let rule = VALID_RULE
            .replace("status: test", "status: experimental")
            .replace(
                "retention: Current setting only.",
                "retention: Current setting only.\nunmeasured_when: [source_empty]",
            );
        let dir = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        write(&dir.join("rule.yaml"), &rule);
        write_empty_tests_dir(&dir);

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains("`unmeasured_when` names `source_empty`"),
            "{:?}",
            outcome.problems
        );
    }

    /// The reasons the four shipped rules declare, and the one the engine itself produces when a
    /// build has no run for the collector at all. `read_failed` is not among them since ADR 0032 —
    /// see `a_reason_a_view_always_lists_cannot_be_declared`.
    #[test]
    fn the_reasons_a_collector_declares_are_accepted() {
        let tmp = TempRoot::new("good-reasons");
        let rule = VALID_RULE.replace(
            "retention: Current setting only.",
            "retention: Current setting only.\nunmeasured_when: [not_windows, source_absent, access_denied, collector_unavailable]",
        );
        let dir = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        write(&dir.join("rule.yaml"), &rule);
        write(&dir.join("tests/positive/on.json"), POSITIVE_FIXTURE);
        write(&dir.join("tests/negative/off.json"), NEGATIVE_FIXTURE);

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);
    }

    /// The `posture` collector reports `read_failed`, so the collector half of this check accepts it
    /// and the rule reads as though the author decided something. ADR 0032: a view lists the reason
    /// whatever the rule said, so the line decides nothing and the gate says so. The four shipped
    /// rules each carried one from before `unmeasured_when` was read by anything.
    #[test]
    fn a_reason_a_view_always_lists_cannot_be_declared() {
        let tmp = TempRoot::new("always-listed-reason");
        let rule = VALID_RULE.replace(
            "retention: Current setting only.",
            "retention: Current setting only.\nunmeasured_when: [read_failed]",
        );
        let dir = tmp.path().join("rules/posture/boot/secure-boot-disabled");
        write(&dir.join("rule.yaml"), &rule);
        write(&dir.join("tests/positive/on.json"), POSITIVE_FIXTURE);
        write(&dir.join("tests/negative/off.json"), NEGATIVE_FIXTURE);

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0]
                .contains("`unmeasured_when` names `read_failed`, which no rule may declare"),
            "{:?}",
            outcome.problems
        );
    }

    /// Every reason a view always lists is refused, not `read_failed` alone — so a later addition to
    /// `is_always_listed` is covered here without this test being edited. `budget_spent` is `evtx`'s
    /// and `partial` is reported by more than one collector, so each is checked on a collector that
    /// can produce it: without that, the message would be the collector one and this test would pass
    /// while proving nothing.
    #[test]
    fn every_always_listed_reason_is_refused() {
        for reason in [
            UnmeasuredReason::Partial,
            UnmeasuredReason::BudgetSpent,
            UnmeasuredReason::ReadFailed,
        ] {
            assert!(
                reason.is_always_listed(),
                "{} is not always listed; this loop is asserting the wrong thing",
                reason.as_str()
            );
        }
        // The reverse direction: nothing outside that set may be refused by this check, or a rule
        // would lose a declaration it is entitled to make.
        for reason in [
            UnmeasuredReason::NotWindows,
            UnmeasuredReason::NotOnThisOs,
            UnmeasuredReason::NotAdmin,
            UnmeasuredReason::NotAttempted,
            UnmeasuredReason::AccessDenied,
            UnmeasuredReason::ServiceDisabled,
            UnmeasuredReason::SourceAbsent,
            UnmeasuredReason::SourceEmpty,
            UnmeasuredReason::CollectorUnavailable,
        ] {
            assert!(
                !reason.is_always_listed(),
                "{} became always listed; a rule that declared it now fails check-rules",
                reason.as_str()
            );
        }
    }

    /// ADR 0027 recorded `not_on_this_os` and `service_disabled` as having no producer anywhere in
    /// this build, so no rule could declare either. ADR 0030 gave each one exactly one owner, and
    /// ADR 0047 amended that table to give `budget_spent` a second owner (`usn`, alongside `evtx`,
    /// both spending the same 30-second-budget idea on two different sources). This is what that
    /// means for the gate: each reason is usable only on the collector(s) that can actually report
    /// it. Asserted against the vocabulary the shipped executable builds, so a collector that later
    /// starts or stops producing one fails here rather than silently accepting a suppression that
    /// never fires, or missing one that now can.
    #[test]
    fn the_revived_reasons_belong_to_one_collector_each() {
        let vocabulary = Vocabulary::of_this_build();
        let reports = |collector: &str, reason: &str| {
            vocabulary
                .reasons
                .get(collector)
                .is_some_and(|reasons| reasons.contains(reason))
        };

        for (reason, owners) in [
            ("not_on_this_os", &["pca"] as &[&str]),
            ("service_disabled", &["prefetch"]),
            ("budget_spent", &["evtx", "usn"]),
            ("not_attempted", &["evtx"]),
        ] {
            for owner in owners {
                assert!(reports(owner, reason), "`{owner}` cannot report `{reason}`");
            }
            for other in rongroi_collectors::all() {
                if owners.contains(&other.id()) {
                    continue;
                }
                assert!(
                    !reports(other.id(), reason),
                    "`{}` also reports `{reason}`; the ADR 0030 table, as amended by ADR 0047, \
                     names only {owners:?} as owners",
                    other.id()
                );
            }
        }
    }

    /// Every collector can be asked which reasons it reports, so the first rule written for any of
    /// them can carry an `unmeasured_when` line.
    #[test]
    fn every_collector_in_the_build_declares_the_reasons_it_reports() {
        let vocabulary = Vocabulary::of_this_build();

        for collector in rongroi_collectors::all() {
            let reasons = vocabulary
                .reasons
                .get(collector.id())
                .unwrap_or_else(|| panic!("collector `{}` declares no reason", collector.id()));
            // `collector_unavailable` is added to every collector's set and belongs to the engine.
            assert!(
                reasons.contains(ENGINE_REASON.as_str()),
                "collector `{}` cannot be expected to be unavailable",
                collector.id()
            );
            assert!(
                reasons.len() > 1,
                "collector `{}` reports no reason of its own",
                collector.id()
            );
        }
    }

    /// The suggestion is a typo detector, not a synonym finder: three edits apart is a different
    /// name, and naming one would send an author to the wrong field.
    #[test]
    fn a_suggestion_is_offered_only_within_two_edits() {
        let known: BTreeMap<&str, FieldKind> = [
            ("run_count", FieldKind::Number),
            ("scca_version", FieldKind::Number),
        ]
        .into_iter()
        .collect();
        assert_eq!(nearest("run_cout", &known), Some("run_count"));
        assert_eq!(nearest("runcount", &known), Some("run_count"));
        assert_eq!(nearest("executions", &known), None);
        assert_eq!(distance("run_count", "run_count"), 0);
        assert_eq!(distance("", "abc"), 3);
    }

    /// Gate (3): an `allow` entry that is not `sha256` or `signer_cert_sha256` (e.g. `file_name`) must be
    /// rejected while parsing the rule, with a message naming the offending field.
    #[test]
    fn allow_entry_with_unknown_field_is_rejected() {
        let tmp = TempRoot::new("bad-allow");
        let rule = format!("{VALID_RULE}allow:\n  - file_name: dxgi.dll\n");
        write(
            &tmp.path()
                .join("rules/posture/boot/secure-boot-disabled/rule.yaml"),
            &rule,
        );

        let error = run(tmp.path()).expect_err("run should reject the unknown allow field");

        let message = error.to_string();
        assert!(
            message
                .contains("unknown field `file_name`, expected one of sha256, signer_cert_sha256"),
            "{message}"
        );
    }

    /// A rule for the `prefetch` collector, so a test can name a numeric field. `experimental`
    /// needs no fixtures, so the `match` block under test is the only expected problem.
    fn prefetch_rule(match_block: &str) -> String {
        format!(
            "id: 2f0c4b1e-8a3d-4c57-9e21-6b0d7f8a1c34\ntitle: t\ndescription: d\nstatus: experimental\ncollector: prefetch\nstrength: execution\nmatch:\n{match_block}retention: What Prefetch still holds.\nfalsepositives: [x]\nauthor: a\ndate: 2026-09-13\n"
        )
    }

    fn problems_for(label: &str, rule: &str) -> Vec<String> {
        let tmp = TempRoot::new(label);
        let dir = tmp.path().join("rules/prefetch/execution/example");
        write(&dir.join("rule.yaml"), rule);
        write_empty_tests_dir(&dir);
        check(tmp.path())
            .expect("check-rules should run to completion")
            .problems
    }

    /// Gate (6): an operator that is not one of ours. Accepting it would evaluate the rule as
    /// something other than what it says (ADR 0029).
    #[test]
    fn an_operator_name_that_is_not_one_of_ours_is_rejected() {
        let problems = problems_for("bad-operator", &prefetch_rule("  run_count|atleast: 2\n"));

        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("asks for `atleast`, which is not an operator"),
            "{problems:?}"
        );
        // The message names the operators there are, so the fix does not need a grep.
        assert!(problems[0].contains("`gte`"), "{problems:?}");
    }

    /// Gate (7): an empty list matches nothing on any machine, and this program shows `not_found`
    /// to a player as a thing looked for and not there.
    #[test]
    fn an_empty_value_list_is_rejected() {
        let problems = problems_for("empty-list", &prefetch_rule("  name: []\n"));

        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("has an empty list"), "{problems:?}");
    }

    /// Gate (8): an ordinal comparison against a field that is only ever text. Nothing in the rule
    /// file says so, and the rule would be `not_found` for ever — the same defect ADR 0026 removed
    /// for field names, arriving through the operator instead.
    #[test]
    fn an_ordinal_comparison_against_a_text_field_is_rejected() {
        let problems = problems_for("ordinal-on-text", &prefetch_rule("  name|gt: 2\n"));

        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains(
                "`match` key `name|gt` puts values in order, which the `prefetch` collector's `name` cannot be: it emits text"
            ),
            "{problems:?}"
        );
    }

    /// The mirror of it: text matching against a field that holds a count.
    #[test]
    fn a_text_operator_against_a_number_field_is_rejected() {
        let problems = problems_for(
            "text-on-number",
            &prefetch_rule("  run_count|contains: '2'\n"),
        );

        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains(
                "`match` key `run_count|contains` matches text, which the `prefetch` collector's `run_count` is not: it emits a number"
            ),
            "{problems:?}"
        );
    }

    /// The value has to suit the field as well as the operator: `last_run` is a timestamp, so a
    /// number can never be put in order against it.
    #[test]
    fn an_ordinal_comparison_whose_value_does_not_suit_the_field_is_rejected() {
        let problems = problems_for("ordinal-wrong-value", &prefetch_rule("  last_run|gte: 2\n"));

        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("the value must be an RFC 3339 timestamp"),
            "{problems:?}"
        );
    }

    /// The positive twin of the four rejections above: every operator, against fields whose kind
    /// takes it, passes.
    #[test]
    fn the_operators_are_accepted_where_the_field_kind_takes_them() {
        let problems = problems_for(
            "good-operators",
            &prefetch_rule(
                "  name: [FiveM.exe, cmd.exe]\n  path|startswith: 'C:\\\\Windows\\\\'\n  path|endswith: .pf\n  path|contains: Prefetch\n  run_count|gte: 2\n  rejected|gt: 0\n  last_run|lt: \"2026-09-13T00:00:00Z\"\n  read|exists: false\n",
            ),
        );

        assert!(problems.is_empty(), "{problems:?}");
    }

    /// Every field a collector declares carries a kind, so the first rule written for any of them
    /// can use an operator.
    #[test]
    fn every_declared_field_has_a_kind_check_rules_can_use() {
        let vocabulary = Vocabulary::of_this_build();

        for collector in rongroi_collectors::all() {
            let fields = vocabulary
                .fields
                .get(collector.id())
                .unwrap_or_else(|| panic!("collector `{}` has no vocabulary", collector.id()));
            assert_eq!(
                fields.len(),
                collector.fields().len(),
                "collector `{}` lost a field on the way into the vocabulary",
                collector.id()
            );
        }
    }
}
