// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask check-rules`: the bundle validation plus fixtures (docs/rules-authoring.md).

use std::collections::BTreeMap;
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

    let mut problems = Vec::new();
    let mut fixture_count = 0;
    for sourced in bundle.rules() {
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
