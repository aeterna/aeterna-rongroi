// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask check-baseline`: the whole rule set against machines described as ordinary (ADR 0017).
//!
//! `check-rules` proves that each rule fires on its own positive fixture and stays quiet on its own
//! negative one. That is a claim about one rule at a time; nothing in it says the *set* is quiet on an
//! ordinary PC. This gate runs every rule against every `fixtures/hosts/baseline-*` host, through the
//! same `scan::run` path the CLI uses, and requires no `Found` evidence except the matches recorded in
//! `rules/known-fps.csv` with a written reason.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use rongroi_collectors::scan::{self, ScanContext};
use rongroi_core::bundle::Bundle;
use rongroi_core::engine::SelfIdentity;
use rongroi_core::model::{EvidenceState, Observation};
use rongroi_core::provenance::Provenance;
use rongroi_host::FixtureHost;

/// Where accepted false positives are recorded, relative to the repository root.
const KNOWN_FPS: &str = "rules/known-fps.csv";
/// Fixture hosts whose name starts with this are baselines: machines asserted to be unremarkable.
const BASELINE_PREFIX: &str = "baseline-";
/// The columns `known-fps.csv` must declare, in this order.
const KNOWN_FPS_COLUMNS: [&str; 4] = ["rule_id", "baseline", "reason", "added"];

/// One accepted match, as written in `known-fps.csv`.
struct KnownFp {
    /// Line in the file, for messages.
    line: usize,
    /// Rule the row accepts a match from.
    rule_id: String,
    /// Baseline the row accepts it on.
    baseline: String,
    /// Why it is accepted. Never empty.
    reason: String,
    /// Whether both the rule and the baseline exist, so the row could be hit at all.
    resolvable: bool,
    /// Whether the match this row describes actually happened.
    hit: bool,
}

/// Everything `run` needs to print or bail on, computed without touching stdout/stderr so tests can
/// assert on the exact problem text instead of only on pass/fail.
struct CheckBaselineOutcome {
    problems: Vec<String>,
    baseline_count: usize,
    known_fp_count: usize,
}

pub fn run(root: &Path) -> anyhow::Result<()> {
    // The bundle the product ships, not one re-read from the tree: a gate that evaluated a different
    // rule set from the executable would prove nothing about the executable (ADR 0017).
    let bundle = Bundle::embedded().context("the embedded rules bundle is invalid")?;
    let outcome = check(root, &bundle)?;
    if outcome.problems.is_empty() {
        println!(
            "check-baseline: {} rule(s) quiet on {} baseline(s), {} known false positive(s) accounted for",
            bundle.rules().len(),
            outcome.baseline_count,
            outcome.known_fp_count
        );
        Ok(())
    } else {
        for problem in &outcome.problems {
            eprintln!("error: {problem}");
        }
        bail!("check-baseline: {} problem(s)", outcome.problems.len())
    }
}

/// `bundle` is a parameter rather than read here so that a test can hand in a bundle built from a
/// temporary tree, and so that `run` can hand in the embedded one.
fn check(root: &Path, bundle: &Bundle) -> anyhow::Result<CheckBaselineOutcome> {
    let mut problems = Vec::new();
    let mut known_fps = read_known_fps(root, &mut problems)?;
    let baselines = baseline_hosts(root)?;

    if baselines.is_empty() {
        problems.push(format!(
            "fixtures/hosts: no `{BASELINE_PREFIX}*` host to run the rules against; with none, this gate measures nothing"
        ));
    }

    let names: BTreeSet<&str> = baselines.iter().map(|(name, _)| name.as_str()).collect();
    validate_rows(&mut known_fps, bundle, &names, &mut problems);

    for (name, dir) in &baselines {
        let host = FixtureHost::load(dir)
            .with_context(|| format!("loading baseline {}", crate::display(root, dir)))?;
        let report = scan::run(&host, bundle, baseline_context());
        for evidence in &report.evidence {
            let EvidenceState::Found { observations } = &evidence.state else {
                continue;
            };
            let mut covered = false;
            for row in &mut known_fps {
                if row.rule_id == evidence.rule_id && row.baseline == *name {
                    row.hit = true;
                    covered = true;
                }
            }
            if !covered {
                problems.push(format!(
                    "fixtures/hosts/{name}: rule `{}` is found on this baseline and no `{KNOWN_FPS}` row accepts it (matched: {})",
                    evidence.rule_id,
                    describe(observations)
                ));
            }
        }
    }

    for row in &known_fps {
        if row.resolvable && !row.hit {
            problems.push(format!(
                "{KNOWN_FPS}:{}: rule `{}` did not match baseline `{}`; an unused row is a claim about the rule set that is no longer true",
                row.line, row.rule_id, row.baseline
            ));
        }
    }

    Ok(CheckBaselineOutcome {
        problems,
        baseline_count: baselines.len(),
        known_fp_count: known_fps.len(),
    })
}

/// A row that names something that does not exist can never be hit, so it is reported once here and
/// left out of the unused-row check rather than being reported twice for the same mistake.
fn validate_rows(
    rows: &mut [KnownFp],
    bundle: &Bundle,
    baselines: &BTreeSet<&str>,
    problems: &mut Vec<String>,
) {
    for row in rows {
        let rule_exists = bundle
            .rules()
            .iter()
            .any(|sourced| sourced.rule.id == row.rule_id);
        if !rule_exists {
            problems.push(format!(
                "{KNOWN_FPS}:{}: rule_id `{}` is not a rule in the bundle",
                row.line, row.rule_id
            ));
        }
        let baseline_exists = baselines.contains(row.baseline.as_str());
        if !baseline_exists {
            problems.push(format!(
                "{KNOWN_FPS}:{}: baseline `{}` is not a `fixtures/hosts/{BASELINE_PREFIX}*` host",
                row.line, row.baseline
            ));
        }
        if row.reason.trim().is_empty() {
            problems.push(format!(
                "{KNOWN_FPS}:{}: `reason` must say why this match is accepted",
                row.line
            ));
        }
        row.resolvable = rule_exists && baseline_exists;
    }
}

/// Scan inputs fixed in place: this gate is about what the rules say, so nothing that varies between
/// runs — a clock, a build, the path this program runs from — may reach the result.
fn baseline_context() -> ScanContext {
    ScanContext {
        provenance: Provenance::from_parts(None, "0.0.0-check-baseline", None, None),
        generated_at: "2026-01-01T00:00:00Z".to_owned(),
        // Nothing in a baseline describes this program, so no observation is an own trace.
        self_identity: SelfIdentity::default(),
    }
}

/// The matching observations, so that a report names what a rule saw and not only that it fired.
fn describe(observations: &[Observation]) -> String {
    observations
        .iter()
        .map(|observation| {
            observation
                .fields
                .iter()
                .map(|(field, value)| format!("{field}={}", render(value)))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// A string field without its JSON quotes; anything else as JSON.
fn render(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}

fn baseline_hosts(root: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let hosts = root.join("fixtures").join("hosts");
    if !hosts.is_dir() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&hosts)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(BASELINE_PREFIX) && entry.path().is_dir() {
            found.push((name, entry.path()));
        }
    }
    found.sort();
    Ok(found)
}

/// Reads `known-fps.csv`. An absent file is no rows, not a problem: a rule set with nothing to accept
/// need not carry the file.
fn read_known_fps(root: &Path, problems: &mut Vec<String>) -> anyhow::Result<Vec<KnownFp>> {
    let path = root.join(KNOWN_FPS);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)?;
    let header = KNOWN_FPS_COLUMNS.join(",");
    let mut rows = Vec::new();
    let mut header_seen = false;
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields = parse_csv_line(trimmed);
        if !header_seen {
            header_seen = true;
            if fields != KNOWN_FPS_COLUMNS {
                problems.push(format!(
                    "{KNOWN_FPS}:{line_number}: the first row must be the header `{header}`"
                ));
            }
            continue;
        }
        let [rule_id, baseline, reason, _added] = fields.as_slice() else {
            problems.push(format!(
                "{KNOWN_FPS}:{line_number}: expected the {} fields of `{header}`, found {}",
                KNOWN_FPS_COLUMNS.len(),
                fields.len()
            ));
            continue;
        };
        rows.push(KnownFp {
            line: line_number,
            rule_id: rule_id.clone(),
            baseline: baseline.clone(),
            reason: reason.clone(),
            resolvable: false,
            hit: false,
        });
    }
    if !header_seen {
        problems.push(format!("{KNOWN_FPS}: the header `{header}` is missing"));
    }
    Ok(rows)
}

/// Splits one CSV row. A field may be double-quoted, which is how a `reason` carries a comma; `""`
/// inside a quoted field is one quote character.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '"' if quoted => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            }
            '"' if field.is_empty() => quoted = true,
            ',' if !quoted => fields.push(std::mem::take(&mut field).trim().to_owned()),
            _ => field.push(character),
        }
    }
    fields.push(field.trim().to_owned());
    fields
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rongroi_core::source_tree::collect_bundle_json;

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
                "aeterna-rongroi-xtask-check-baseline-{}-{label}-{n}-{nanos}",
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

    const RULE_ID: &str = "7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7";

    /// Modelled on the real `rules/posture/boot/secure-boot-disabled/rule.yaml`, as `experimental` so
    /// that this tree needs no rule fixtures — those are `check-rules`' subject, not this gate's.
    const RULE: &str = "id: 7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7
title: Secure Boot is turned off
description: Windows reports that UEFI Secure Boot is off.
status: experimental
collector: posture
strength: posture
match:
  secure_boot: disabled
retention: Current setting only.
falsepositives:
  - PCs that boot in legacy BIOS or CSM mode
author: aeterna-rongroi contributors
date: 2026-09-12
";

    /// A baseline the rule above matches, so the gate has something to report.
    const LOUD_HOST: &str = r"platform: windows
registry:
  'HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State':
    UEFISecureBootEnabled: 0
code_integrity:
  enabled: true
  test_signing: false
tpm:
  present: true
";

    /// The same machine with Secure Boot on: nothing in the bundle matches it.
    const QUIET_HOST: &str = r"platform: windows
registry:
  'HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State':
    UEFISecureBootEnabled: 1
code_integrity:
  enabled: true
  test_signing: false
tpm:
  present: true
";

    /// Writes the rule tree and one baseline, and returns the bundle built from that tree.
    fn tree_with(root: &Path, baseline: &str, host: &str) -> Bundle {
        write(
            &root.join("rules/posture/boot/secure-boot-disabled/rule.yaml"),
            RULE,
        );
        write(
            &root.join("fixtures/hosts").join(baseline).join("host.yaml"),
            host,
        );
        let json = collect_bundle_json(&root.join("rules")).expect("collect the temporary bundle");
        Bundle::from_bundle_json(&json).expect("the temporary bundle is valid")
    }

    fn known_fps(root: &Path, rows: &str) {
        write(
            &root.join(KNOWN_FPS),
            &format!("{}\n{rows}", KNOWN_FPS_COLUMNS.join(",")),
        );
    }

    /// The shape the gate exists to certify: every rule quiet on a machine described as ordinary.
    #[test]
    fn a_baseline_no_rule_matches_has_no_problems() {
        let tmp = TempRoot::new("quiet");
        let bundle = tree_with(tmp.path(), "baseline-quiet", QUIET_HOST);

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);
        assert_eq!(outcome.baseline_count, 1);
    }

    /// A rule that fires on an ordinary machine is what this gate is for. Every other gate in the
    /// repository passes on this tree.
    #[test]
    fn a_match_on_a_baseline_with_no_row_is_reported() {
        let tmp = TempRoot::new("uncovered");
        let bundle = tree_with(tmp.path(), "baseline-loud", LOUD_HOST);

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(&format!(
                "fixtures/hosts/baseline-loud: rule `{RULE_ID}` is found on this baseline and no `{KNOWN_FPS}` row accepts it"
            )),
            "{:?}",
            outcome.problems
        );
        // The message names what the rule saw, not only that it fired.
        assert!(
            outcome.problems[0].contains("secure_boot=disabled"),
            "{:?}",
            outcome.problems
        );
    }

    #[test]
    fn a_match_a_known_fp_row_accepts_is_not_a_problem() {
        let tmp = TempRoot::new("covered");
        let bundle = tree_with(tmp.path(), "baseline-loud", LOUD_HOST);
        known_fps(
            tmp.path(),
            &format!(
                "{RULE_ID},baseline-loud,\"Legacy BIOS boot, which this profile describes\",2026-09-12\n"
            ),
        );

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);
        assert_eq!(outcome.known_fp_count, 1);
    }

    /// A rule id that no longer exists is permission granted to nothing. The file would otherwise
    /// keep accumulating rows for rules that changed or were deleted.
    #[test]
    fn a_row_naming_an_unknown_rule_is_reported() {
        let tmp = TempRoot::new("stale-rule");
        let bundle = tree_with(tmp.path(), "baseline-quiet", QUIET_HOST);
        known_fps(
            tmp.path(),
            "00000000-0000-4000-8000-000000000000,baseline-quiet,Something,2026-09-12\n",
        );

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(
                "rules/known-fps.csv:2: rule_id `00000000-0000-4000-8000-000000000000` is not a rule in the bundle"
            ),
            "{:?}",
            outcome.problems
        );
    }

    #[test]
    fn a_row_naming_an_unknown_baseline_is_reported() {
        let tmp = TempRoot::new("stale-baseline");
        let bundle = tree_with(tmp.path(), "baseline-quiet", QUIET_HOST);
        known_fps(
            tmp.path(),
            &format!("{RULE_ID},baseline-gone,Something,2026-09-12\n"),
        );

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(
                "rules/known-fps.csv:2: baseline `baseline-gone` is not a `fixtures/hosts/baseline-*` host"
            ),
            "{:?}",
            outcome.problems
        );
    }

    /// A row with no reason is how this file becomes a rubber stamp, so it is a failure rather than
    /// an untidy entry. The match itself is still accepted, so this is the only problem.
    #[test]
    fn a_row_without_a_reason_is_reported() {
        let tmp = TempRoot::new("no-reason");
        let bundle = tree_with(tmp.path(), "baseline-loud", LOUD_HOST);
        known_fps(
            tmp.path(),
            &format!("{RULE_ID},baseline-loud,  ,2026-09-12\n"),
        );

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0]
                .contains("rules/known-fps.csv:2: `reason` must say why this match is accepted"),
            "{:?}",
            outcome.problems
        );
    }

    /// The row names a rule and a baseline that both exist, and the rule does not match there. The
    /// permission is real and unused, which says something about the rule set that is not true.
    #[test]
    fn a_row_no_match_hit_is_reported() {
        let tmp = TempRoot::new("unused");
        let bundle = tree_with(tmp.path(), "baseline-quiet", QUIET_HOST);
        known_fps(
            tmp.path(),
            &format!("{RULE_ID},baseline-quiet,\"It used to match here\",2026-09-12\n"),
        );

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(&format!(
                "rules/known-fps.csv:2: rule `{RULE_ID}` did not match baseline `baseline-quiet`"
            )),
            "{:?}",
            outcome.problems
        );
    }

    /// With no baseline at all every rule is trivially quiet, which is the one way this gate could
    /// report success while measuring nothing.
    #[test]
    fn a_tree_with_no_baseline_host_is_reported() {
        let tmp = TempRoot::new("no-baseline");
        write(
            &tmp.path()
                .join("rules/posture/boot/secure-boot-disabled/rule.yaml"),
            RULE,
        );
        let json =
            collect_bundle_json(&tmp.path().join("rules")).expect("collect the temporary bundle");
        let bundle = Bundle::from_bundle_json(&json).expect("the temporary bundle is valid");

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains("no `baseline-*` host to run the rules against"),
            "{:?}",
            outcome.problems
        );
    }

    /// A `reason` is prose and will contain commas, so the quoting has to survive a round trip.
    #[test]
    fn a_quoted_reason_keeps_its_commas() {
        assert_eq!(
            parse_csv_line(r#"id,baseline-a,"one, two, three",2026-09-12"#),
            ["id", "baseline-a", "one, two, three", "2026-09-12"]
        );
        assert_eq!(
            parse_csv_line(r#"id,baseline-a,"a ""quoted"" word",2026-09-12"#),
            ["id", "baseline-a", r#"a "quoted" word"#, "2026-09-12"]
        );
    }
}
