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

pub fn run(root: &Path) -> anyhow::Result<()> {
    let rules_dir = root.join("rules");
    let json = collect_bundle_json(&rules_dir)?;
    let bundle = match Bundle::from_bundle_json(&json) {
        Ok(bundle) => bundle,
        Err(BundleError::Invalid(problems)) => {
            for problem in &problems {
                eprintln!("error: {problem}");
            }
            bail!("check-rules: {} problem(s)", problems.len());
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

    if problems.is_empty() {
        println!(
            "check-rules: {} rule(s), {fixture_count} fixture(s), {} language(s) ok",
            bundle.rules().len(),
            bundle.languages().len()
        );
        Ok(())
    } else {
        for problem in &problems {
            eprintln!("error: {problem}");
        }
        bail!("check-rules: {} problem(s)", problems.len())
    }
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
