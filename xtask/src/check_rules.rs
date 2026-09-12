// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask check-rules`: the bundle validation plus fixtures (docs/rules-authoring.md).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::bail;
use rongroi_core::bundle::{Bundle, BundleError};
use rongroi_core::engine;
use rongroi_core::model::{CollectorRun, EvidenceState, Observation, UnmeasuredReason};
use rongroi_core::rules::Rule;
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
    let mut fixture_count = 0;
    for sourced in bundle.rules() {
        vocabulary.check(&sourced.path, &sourced.rule, &mut problems);
        let rule_folder = rules_dir.join(sourced.path.trim_end_matches("rule.yaml"));
        let tests_dir = rule_folder.join("tests");
        let positive = json_files(&tests_dir.join("positive"))?;
        let negative = json_files(&tests_dir.join("negative"))?;

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
    fields: BTreeMap<&'static str, BTreeSet<&'static str>>,
}

impl Vocabulary {
    fn of_this_build() -> Self {
        Self {
            fields: rongroi_collectors::all()
                .iter()
                .map(|collector| (collector.id(), collector.fields().iter().copied().collect()))
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
        for field in rule.matcher.keys() {
            if known.contains(field.as_str()) {
                continue;
            }
            let suggestion = nearest(field, known)
                .map_or_else(String::new, |name| format!(" (did you mean `{name}`?)"));
            problems.push(format!(
                "rules/{path}: `match` names `{field}`, which the `{}` collector cannot emit{suggestion}; it emits {}",
                rule.collector,
                comma(known.iter().copied())
            ));
        }
    }
}

/// The declared name closest to `field`, when one is close enough to be a misspelling of it rather
/// than a different name. Two edits is the widest gap that is still more likely a typo than a choice.
fn nearest<'a>(field: &str, known: &BTreeSet<&'a str>) -> Option<&'a str> {
    known
        .iter()
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

    /// Gate (1): two rules sharing the same `id` must be rejected.
    #[test]
    fn duplicate_rule_id_is_rejected() {
        let tmp = TempRoot::new("dup-id");
        // `experimental` does not need fixtures, so the only expected problem is the duplicate id.
        let rule = VALID_RULE.replace("status: test", "status: experimental");
        write(
            &tmp.path()
                .join("rules/posture/boot/secure-boot-disabled/rule.yaml"),
            &rule,
        );
        write(
            &tmp.path()
                .join("rules/posture/boot/secure-boot-disabled-copy/rule.yaml"),
            &rule,
        );

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
        // `experimental` needs no fixtures, so the collector id is the only expected problem.
        let rule = VALID_RULE
            .replace("status: test", "status: experimental")
            .replace("collector: posture", "collector: postures");
        write(
            &tmp.path()
                .join("rules/postures/boot/secure-boot-disabled/rule.yaml"),
            &rule,
        );

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
        write(
            &tmp.path()
                .join("rules/posture/boot/secure-boot-disabled/rule.yaml"),
            &rule,
        );

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
        write(
            &tmp.path()
                .join("rules/posture/boot/secure-boot-disabled/rule.yaml"),
            &rule,
        );

        let outcome = check(tmp.path()).expect("check-rules should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            !outcome.problems[0].contains("did you mean"),
            "{:?}",
            outcome.problems
        );
        assert!(
            outcome.problems[0]
                .contains("it emits hvci, secure_boot, test_signing, tpm, tpm_spec_version"),
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

    /// The suggestion is a typo detector, not a synonym finder: three edits apart is a different
    /// name, and naming one would send an author to the wrong field.
    #[test]
    fn a_suggestion_is_offered_only_within_two_edits() {
        let known: BTreeSet<&str> = ["run_count", "scca_version"].into_iter().collect();
        assert_eq!(nearest("run_cout", &known), Some("run_count"));
        assert_eq!(nearest("runcount", &known), Some("run_count"));
        assert_eq!(nearest("executions", &known), None);
        assert_eq!(distance("run_count", "run_count"), 0);
        assert_eq!(distance("", "abc"), 3);
    }

    /// Gate (3): an `allow` entry that is not `sha256` or `signer` (e.g. `file_name`) must be
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
            message.contains("unknown field `file_name`, expected one of sha256, signer"),
            "{message}"
        );
    }
}
