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
//!
//! # Quiet for the right reason (ADR 0033)
//!
//! Requiring no `Found` is satisfied by a rule that was never compared to anything of its own shape.
//! The two log-clearing rules match `provider`, `channel` and `event_id` on the `Security` and
//! `System` channels; no baseline carries either channel, so the observations they meet agree with
//! none of their three conditions and they are quiet whatever they say. That is a green this gate
//! produced without measuring anything, of the same kind ADR 0026 closed for four collectors.
//!
//! So each rule must also be **confronted**: some baseline observation of its collector must carry
//! the fields it names and come within one condition of firing it — see
//! [`rongroi_core::engine::confronts`]. A rule no baseline confronts is reported unless
//! `rules/unconfronted.csv` carries a row saying why and what would end it, and a row for a rule that
//! *is* confronted is reported too, exactly as an unused `known-fps.csv` row is.
//!
//! An observation that differs from a rule only in its collector's **discriminator** — `fivem_dir`'s
//! `location` — does not confront it: it is about another place (ADR 0033 as amended, ADR 0044). The
//! gate says so by name when that is the only near miss a rule has, so the author is not left to work
//! out why a rule that looks confronted is not.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use rongroi_collectors::scan::{self, ScanContext};
use rongroi_core::bundle::Bundle;
use rongroi_core::engine::{SelfIdentity, confronts};
use rongroi_core::model::{EvidenceState, Observation, Report};
use rongroi_core::provenance::Provenance;
use rongroi_host::FixtureHost;

/// Where accepted false positives are recorded, relative to the repository root.
const KNOWN_FPS: &str = "rules/known-fps.csv";
/// Where rules no baseline confronts are recorded, relative to the repository root.
const UNCONFRONTED: &str = "rules/unconfronted.csv";
/// Fixture hosts whose name starts with this are baselines: machines asserted to be unremarkable.
const BASELINE_PREFIX: &str = "baseline-";
/// The columns `known-fps.csv` must declare, in this order.
const KNOWN_FPS_COLUMNS: [&str; 4] = ["rule_id", "baseline", "reason", "added"];
/// The columns `unconfronted.csv` must declare, in this order.
///
/// `resolved_when` has no counterpart in `known-fps.csv` and is the point of the file: a row here
/// records a hole rather than an accepted result, and a hole with no written way out is one nobody
/// will close (the workspace standard's §9.5, applied to a gate instead of to a branch).
const UNCONFRONTED_COLUMNS: [&str; 4] = ["rule_id", "reason", "resolved_when", "added"];

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

/// One rule whose hole is accepted for now, as written in `unconfronted.csv`.
struct Unconfronted {
    /// Line in the file, for messages.
    line: usize,
    /// Rule the row excuses.
    rule_id: String,
    /// Why no baseline confronts it. Never empty.
    reason: String,
    /// What would make the row unnecessary. Never empty.
    resolved_when: String,
    /// Whether the rule exists, so the row could be needed at all.
    resolvable: bool,
}

/// Everything `run` needs to print or bail on, computed without touching stdout/stderr so tests can
/// assert on the exact problem text instead of only on pass/fail.
struct CheckBaselineOutcome {
    problems: Vec<String>,
    baseline_count: usize,
    known_fp_count: usize,
    confronted_count: usize,
    unconfronted_count: usize,
}

pub fn run(root: &Path) -> anyhow::Result<()> {
    // The bundle the product ships, not one re-read from the tree: a gate that evaluated a different
    // rule set from the executable would prove nothing about the executable (ADR 0017).
    let bundle = Bundle::embedded().context("the embedded rules bundle is invalid")?;
    let outcome = check(root, &bundle)?;
    if outcome.problems.is_empty() {
        println!(
            "check-baseline: {} rule(s) quiet on {} baseline(s), {} confronted, {} excused in {UNCONFRONTED}, {} known false positive(s) accounted for",
            bundle.rules().len(),
            outcome.baseline_count,
            outcome.confronted_count,
            outcome.unconfronted_count,
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
    let mut unconfronted = read_unconfronted(root, &mut problems)?;
    let mut confronted: BTreeSet<String> = BTreeSet::new();
    // Rules some baseline observation came one condition from firing, where that condition was the
    // discriminator: confronted by ADR 0033's first definition and not by its amended one.
    let mut other_place_only: BTreeSet<String> = BTreeSet::new();
    let discriminators: BTreeMap<&'static str, &'static str> = rongroi_collectors::all()
        .iter()
        .filter_map(|collector| Some((collector.id(), collector.discriminator()?)))
        .collect();
    let baselines = baseline_hosts(root)?;

    if baselines.is_empty() {
        problems.push(format!(
            "fixtures/hosts: no `{BASELINE_PREFIX}*` host to run the rules against; with none, this gate measures nothing"
        ));
    }

    let names: BTreeSet<&str> = baselines.iter().map(|(name, _)| name.as_str()).collect();
    validate_rows(&mut known_fps, bundle, &names, &mut problems);
    validate_unconfronted(&mut unconfronted, bundle, &mut problems);

    for (name, dir) in &baselines {
        let host = FixtureHost::load(dir)
            .with_context(|| format!("loading baseline {}", crate::display(root, dir)))?;
        let report = scan::run(&host, bundle, baseline_context());
        let seen = observations_in(&report);
        for sourced in bundle.rules() {
            let rule = &sourced.rule;
            let discriminator = discriminators.get(rule.collector.as_str()).copied();
            if seen
                .iter()
                .any(|observation| confronts(rule, observation, discriminator))
            {
                confronted.insert(rule.id.clone());
            } else if seen
                .iter()
                .any(|observation| confronts(rule, observation, None))
            {
                other_place_only.insert(rule.id.clone());
            }
        }
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

    // Only worth asking once there is a baseline to ask it of: with none, every rule is unconfronted
    // for the reason already reported above, and repeating it per rule would bury it.
    if !baselines.is_empty() {
        other_place_only.retain(|id| !confronted.contains(id));
        let near_misses = NearMisses {
            other_place_only: &other_place_only,
            discriminators: &discriminators,
        };
        report_unconfronted(
            bundle,
            &confronted,
            &near_misses,
            &unconfronted,
            &mut problems,
        );
    }

    Ok(CheckBaselineOutcome {
        problems,
        baseline_count: baselines.len(),
        known_fp_count: known_fps.len(),
        confronted_count: confronted.len(),
        unconfronted_count: unconfronted.len(),
    })
}

/// Every observation the baseline produced, whichever bucket the report put it in.
///
/// `unmatched` holds the ones no active rule matched and each `found` entry the ones its rule did,
/// so the two together are the whole of what the collectors saw; `own_traces` is always empty here
/// because [`baseline_context`] hands the engine no identity, and is included so that stays a fact
/// about the context rather than a thing this function assumes.
fn observations_in(report: &Report) -> Vec<&Observation> {
    let found = report
        .evidence
        .iter()
        .filter_map(|evidence| match &evidence.state {
            EvidenceState::Found { observations } => Some(observations.iter()),
            _ => None,
        });
    found
        .flatten()
        .chain(
            report
                .unmatched
                .iter()
                .flat_map(|group| &group.observations),
        )
        .chain(report.own_traces.iter().map(|entry| &entry.observation))
        .collect()
}

/// The rules whose only near misses on the baselines were about another place, and the field that
/// says which place for each collector that has one.
struct NearMisses<'a> {
    other_place_only: &'a BTreeSet<String>,
    discriminators: &'a BTreeMap<&'static str, &'static str>,
}

/// Reports every rule no baseline confronted and has no row for, and every row for a rule that was
/// confronted after all.
fn report_unconfronted(
    bundle: &Bundle,
    confronted: &BTreeSet<String>,
    near_misses: &NearMisses<'_>,
    rows: &[Unconfronted],
    problems: &mut Vec<String>,
) {
    for sourced in bundle.rules() {
        let rule = &sourced.rule;
        if confronted.contains(&rule.id) || rows.iter().any(|row| row.rule_id == rule.id) {
            continue;
        }
        let why = match near_misses.discriminators.get(rule.collector.as_str()) {
            Some(field) if near_misses.other_place_only.contains(&rule.id) => format!(
                "the only observations one condition from firing it differ from it in `{field}`, the `{}` collector's discriminator, so they are about another place and were never asked this rule's question (ADR 0033, ADR 0044)",
                rule.collector
            ),
            _ => "no observation carries the fields its `match` names and comes within one condition of firing it".to_owned(),
        };
        problems.push(format!(
            "rules/{}: no baseline confronts rule `{}` — {why}, so this gate cannot tell a correct rule from a wrong one here. Add a baseline that holds the shape it reads, or a `{UNCONFRONTED}` row saying why not and what would end it",
            sourced.path, rule.id
        ));
    }
    for row in rows {
        if row.resolvable && confronted.contains(&row.rule_id) {
            problems.push(format!(
                "{UNCONFRONTED}:{}: rule `{}` is confronted by a baseline now; an excused hole that has closed is a claim about the rule set that is no longer true (the row said it would end when: {})",
                row.line, row.rule_id, row.resolved_when
            ));
        }
    }
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

/// Reads `unconfronted.csv`. An absent file is no rows, which is the state a rule set every baseline
/// confronts should be in.
fn read_unconfronted(root: &Path, problems: &mut Vec<String>) -> anyhow::Result<Vec<Unconfronted>> {
    let path = root.join(UNCONFRONTED);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)?;
    let header = UNCONFRONTED_COLUMNS.join(",");
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
            if fields != UNCONFRONTED_COLUMNS {
                problems.push(format!(
                    "{UNCONFRONTED}:{line_number}: the first row must be the header `{header}`"
                ));
            }
            continue;
        }
        let [rule_id, reason, resolved_when, _added] = fields.as_slice() else {
            problems.push(format!(
                "{UNCONFRONTED}:{line_number}: expected the {} fields of `{header}`, found {}",
                UNCONFRONTED_COLUMNS.len(),
                fields.len()
            ));
            continue;
        };
        rows.push(Unconfronted {
            line: line_number,
            rule_id: rule_id.clone(),
            reason: reason.clone(),
            resolved_when: resolved_when.clone(),
            resolvable: false,
        });
    }
    if !header_seen {
        problems.push(format!("{UNCONFRONTED}: the header `{header}` is missing"));
    }
    Ok(rows)
}

/// Rejects a row that excuses nothing that exists, and one that excuses without saying anything.
fn validate_unconfronted(rows: &mut [Unconfronted], bundle: &Bundle, problems: &mut Vec<String>) {
    for row in rows {
        let exists = bundle
            .rules()
            .iter()
            .any(|sourced| sourced.rule.id == row.rule_id);
        if !exists {
            problems.push(format!(
                "{UNCONFRONTED}:{}: rule_id `{}` is not a rule in the bundle",
                row.line, row.rule_id
            ));
        }
        if row.reason.trim().is_empty() {
            problems.push(format!(
                "{UNCONFRONTED}:{}: `reason` must say why no baseline confronts this rule",
                row.line
            ));
        }
        if row.resolved_when.trim().is_empty() {
            problems.push(format!(
                "{UNCONFRONTED}:{}: `resolved_when` must say what would end this row; a hole with no written way out is one nobody closes",
                row.line
            ));
        }
        row.resolvable = exists;
    }
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

    /// A Windows machine the `posture` collector cannot read the Secure Boot state of: the key is
    /// not there, so `secure_boot` is a gap rather than a value, and no observation carries the field
    /// the rule names. The rule is quiet here for a reason that says nothing about the rule.
    const BLIND_HOST: &str = r"platform: windows
code_integrity:
  enabled: true
  test_signing: false
tpm:
  present: true
";

    fn known_fps(root: &Path, rows: &str) {
        write(
            &root.join(KNOWN_FPS),
            &format!("{}\n{rows}", KNOWN_FPS_COLUMNS.join(",")),
        );
    }

    fn unconfronted(root: &Path, rows: &str) {
        write(
            &root.join(UNCONFRONTED),
            &format!("{}\n{rows}", UNCONFRONTED_COLUMNS.join(",")),
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

    /// The hole ADR 0033 is for. Every other check in this gate passes on this tree: the rule is
    /// quiet on the baseline, no `known-fps.csv` row is needed, and nothing anywhere says the reason
    /// it is quiet is that the baseline never carried the field it reads.
    #[test]
    fn a_rule_no_baseline_confronts_is_reported() {
        let tmp = TempRoot::new("unconfronted");
        let bundle = tree_with(tmp.path(), "baseline-blind", BLIND_HOST);

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(&format!("no baseline confronts rule `{RULE_ID}`")),
            "{:?}",
            outcome.problems
        );
        assert_eq!(outcome.confronted_count, 0);
    }

    /// The same tree with the hole written down. The gate still reports nothing green about the rule
    /// — it reports nothing at all — which is the whole claim a row makes.
    #[test]
    fn an_unconfronted_rule_with_a_row_is_accepted() {
        let tmp = TempRoot::new("unconfronted-excused");
        let bundle = tree_with(tmp.path(), "baseline-blind", BLIND_HOST);
        unconfronted(
            tmp.path(),
            &format!(
                "{RULE_ID},\"No baseline reports the Secure Boot state\",\"A baseline whose registry carries the key\",2026-09-13\n"
            ),
        );

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);
        assert_eq!(outcome.unconfronted_count, 1);
    }

    /// The direction that makes the file self-clearing: once a baseline carries the shape, the row is
    /// a statement about the rule set that is no longer true, and CI requires its removal.
    #[test]
    fn a_row_for_a_rule_a_baseline_confronts_is_reported() {
        let tmp = TempRoot::new("unconfronted-stale");
        let bundle = tree_with(tmp.path(), "baseline-quiet", QUIET_HOST);
        unconfronted(
            tmp.path(),
            &format!("{RULE_ID},\"Nothing reads this\",\"A baseline that does\",2026-09-13\n"),
        );

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0]
                .contains(&format!("rule `{RULE_ID}` is confronted by a baseline now")),
            "{:?}",
            outcome.problems
        );
    }

    /// A baseline that answers the rule's question needs no row and gets no complaint. This is the
    /// state the shipped rule set is in for four of its six rules.
    #[test]
    fn a_rule_a_baseline_confronts_needs_no_row() {
        let tmp = TempRoot::new("confronted");
        let bundle = tree_with(tmp.path(), "baseline-quiet", QUIET_HOST);

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);
        assert_eq!(outcome.confronted_count, 1);
    }

    #[test]
    fn an_unconfronted_row_naming_an_unknown_rule_is_reported() {
        let tmp = TempRoot::new("unconfronted-unknown-rule");
        let bundle = tree_with(tmp.path(), "baseline-quiet", QUIET_HOST);
        unconfronted(
            tmp.path(),
            "00000000-0000-4000-8000-000000000000,Something,Something else,2026-09-13\n",
        );

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(
                "rules/unconfronted.csv:2: rule_id `00000000-0000-4000-8000-000000000000` is not a rule in the bundle"
            ),
            "{:?}",
            outcome.problems
        );
    }

    /// Without this the file becomes a list of permanent excuses, which is the shape that made the
    /// original green worthless in the first place.
    #[test]
    fn an_unconfronted_row_without_a_way_out_is_reported() {
        let tmp = TempRoot::new("unconfronted-no-exit");
        let bundle = tree_with(tmp.path(), "baseline-blind", BLIND_HOST);
        unconfronted(
            tmp.path(),
            &format!("{RULE_ID},\"No baseline reports it\",  ,2026-09-13\n"),
        );

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains("`resolved_when` must say what would end this row"),
            "{:?}",
            outcome.problems
        );
    }

    const PLUGIN_RULE_ID: &str = "d5531c55-1a65-4698-9f39-7cf79bbbb7ba";

    /// Modelled on `rules/fivem_dir/plugins/plugin-file-with-valid-signature/rule.yaml`.
    const PLUGIN_RULE: &str = "id: d5531c55-1a65-4698-9f39-7cf79bbbb7ba
title: A file in FiveM's plugins folder carries a valid embedded signature
description: A file in the plugins folder has a valid embedded signature.
status: experimental
collector: fivem_dir
strength: presence
match:
  location: plugins
  signature: valid
retention: Only the files in the folder when the scan ran.
falsepositives:
  - Signed overlays
author: aeterna-rongroi contributors
date: 2026-09-14
";

    /// A `FiveM` install as the consumer baseline describes it: an empty plugins folder, and `FiveM.exe`
    /// validly signed. `plugins` is the listing of the plugins folder, as YAML.
    fn fivem_host(plugins: &str) -> String {
        format!(
            r"platform: windows
env:
  LOCALAPPDATA: 'C:\Users\fixtureuser\AppData\Local'
  APPDATA: 'C:\Users\fixtureuser\AppData\Roaming'
filesystem:
  'C:\Users\fixtureuser\AppData\Local\FiveM\FiveM.app\plugins': {plugins}
  'C:\Users\fixtureuser\AppData\Local\FiveM':
    - name: FiveM.exe
      signature:
        state: valid
        signer: Example Signer
        signer_cert_sha256: {cert}
",
            cert = "b".repeat(64)
        )
    }

    fn fivem_tree(root: &Path, host: &str) -> Bundle {
        write(
            &root.join("rules/fivem_dir/plugins/plugin-file-with-valid-signature/rule.yaml"),
            PLUGIN_RULE,
        );
        write(&root.join("fixtures/hosts/baseline-fivem/host.yaml"), host);
        let json = collect_bundle_json(&root.join("rules")).expect("collect the temporary bundle");
        Bundle::from_bundle_json(&json).expect("the temporary bundle is valid")
    }

    /// ADR 0033, amended 2026-09-14. The only observation carrying both fields is `FiveM.exe`, which
    /// differs from the rule in `location` alone. Before the amendment this counted as confronted, and
    /// a misspelt `location:` in the rule would have gone on counting — measured on the shipped rule.
    /// The gate now refuses it and says the near miss was about another place.
    #[test]
    fn a_rule_near_missed_only_in_the_discriminator_is_not_confronted() {
        let tmp = TempRoot::new("discriminator-only");
        let bundle = fivem_tree(tmp.path(), &fivem_host("[]"));

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert_eq!(outcome.problems.len(), 1, "{:?}", outcome.problems);
        assert!(
            outcome.problems[0].contains(&format!("no baseline confronts rule `{PLUGIN_RULE_ID}`"))
                && outcome.problems[0].contains(
                    "differ from it in `location`, the `fivem_dir` collector's discriminator"
                ),
            "{:?}",
            outcome.problems
        );
        assert_eq!(outcome.confronted_count, 0);
    }

    /// The positive twin: a baseline plugin file whose signature is another answer is in the rule's
    /// own place and one condition away, so it confronts the rule.
    #[test]
    fn a_rule_near_missed_in_its_own_place_is_confronted() {
        let tmp = TempRoot::new("discriminator-same-place");
        let bundle = fivem_tree(
            tmp.path(),
            &fivem_host(
                "\n    - name: dxgi.dll\n      signature:\n        state: no_embedded_signature",
            ),
        );

        let outcome = check(tmp.path(), &bundle).expect("check-baseline should run to completion");

        assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);
        assert_eq!(outcome.confronted_count, 1);
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
