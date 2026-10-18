// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask coverage`: `docs/coverage.md`, the table ADR 0074 §2 asks for, written from the rules,
//! the baseline lists, the retention texts and the measurement ledger.
//!
//! This module reads the inputs and builds the [`Table`]; `page` renders it. The table reports counts
//! and lists and never a percentage or a score (ADR 0074 §3), and a gap in it never fails CI (§4).
//! Nothing here reads the clock, the network or a machine, so the same repository gives the same page.
//!
//! A reader's problem stops the command: a broken ledger must not yield a table that looks complete.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, bail};
use rongroi_core::bundle::{Bundle, BundleError};
use rongroi_core::rules::Status;
use rongroi_core::source_tree::collect_bundle_json;

use crate::check_baseline;
use crate::measured::{self, Edition, Measured, Seen, Token};

/// The command a stale page is fixed with. Printed by `--check`.
pub(crate) const COMMAND: &str = "cargo xtask coverage";
/// The page this command writes, relative to the repository root.
pub(crate) const PAGE: &str = "docs/coverage.md";

/// The first Windows build that is Windows 11; a leading build number below this is Windows 10.
const WINDOWS_11_FIRST_BUILD: u32 = 22_000;

#[derive(clap::Args)]
pub struct Args {
    /// Do not write anything; fail if `docs/coverage.md` differs from what the inputs produce.
    #[arg(long)]
    check: bool,
}

/// Everything the page shows, computed once from the inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Table {
    /// One row per rule, sorted by collector, then rule directory.
    pub(crate) rows: Vec<RuleRow>,
    /// One row per distinct collector of a bundle rule, sorted by id.
    pub(crate) collectors: Vec<CollectorRow>,
    /// One row per `rules/unconfronted.csv` row that names a bundle rule, oldest `added` first,
    /// then rule directory.
    pub(crate) unconfronted: Vec<UnconfrontedGap>,
    /// Ledger rows whose subject is a collector, whatever their `seen`.
    pub(crate) ledger_collector_rows: usize,
    /// Ledger rows whose subject is a rule, whatever their `seen`.
    pub(crate) ledger_rule_rows: usize,
}

/// One rule, as one row of the page's rule table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleRow {
    /// Rule path without `/rule.yaml`, such as `posture/boot/secure-boot-off`.
    pub(crate) dir: String,
    /// The collector the rule reads.
    pub(crate) collector: String,
    /// `evidence` or `timeline`, as in `rule.yaml`.
    pub(crate) role: &'static str,
    /// The strength, as in `rule.yaml`.
    pub(crate) strength: &'static str,
    /// The status, as in `rule.yaml` (`experimental`, `test`, `stable`, `deprecated`).
    pub(crate) status: &'static str,
    /// Number of `tests/positive` fixtures.
    pub(crate) positive: usize,
    /// Number of `tests/negative` fixtures.
    pub(crate) negative: usize,
    /// Whether a `rules/known-fps.csv` row names the rule.
    pub(crate) known_fp: bool,
    /// Whether a `rules/unconfronted.csv` row names the rule.
    pub(crate) unconfronted: bool,
    /// The retention the rule's collector has in `rules/ages`.
    pub(crate) retention: Retention,
    /// Distinct `<machine> <os_build>` of this rule's ledger rows with `seen = found`, sorted.
    pub(crate) seen_found: Vec<String>,
    /// Distinct `<os_build> <edition> <arch>` of the collector's ledger rows with `seen` observations
    /// or none, sorted.
    pub(crate) measured_on: Vec<String>,
}

/// Where a rule's look-back comes from, for its collector (ADR 0061).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Retention {
    /// `rules/ages` records a retention Microsoft documents.
    Documented,
    /// `rules/ages` records a retention the text states on other grounds.
    Stated,
    /// The collector has no `rules/ages` file.
    None,
}

impl Retention {
    /// The spelling this value has on the page.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Documented => "documented",
            Self::Stated => "stated",
            Self::None => "none",
        }
    }
}

/// One collector of the bundle's rules, and what the ledger says about it.
// Four flags, each a separate question the page asks of a collector; a state type would hide them.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CollectorRow {
    /// The collector's id, which is also the `collector` of its rules.
    pub(crate) id: String,
    /// Distinct `os_build` of the collector's ledger rows with `seen` observations or none.
    pub(crate) builds: BTreeSet<String>,
    /// Whether any such row was measured on a `client` edition.
    pub(crate) client: bool,
    /// Whether any such row has a build whose leading number is below 22000 (Windows 10).
    pub(crate) windows10: bool,
    /// Whether any such row ran with a `limited` token.
    pub(crate) limited: bool,
    /// Whether `rules/ages` has a file for this collector.
    pub(crate) has_ages: bool,
}

/// A rule whose hole is excused for now, as one row of `rules/unconfronted.csv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnconfrontedGap {
    /// Rule path without `/rule.yaml`.
    pub(crate) dir: String,
    /// The row's `added` column, as written.
    pub(crate) added: String,
    /// The row's `resolved_when`, as written.
    pub(crate) resolved_when: String,
}

pub fn run(root: &Path, args: &Args) -> anyhow::Result<()> {
    let text = render(root)?;
    if !args.check {
        std::fs::write(root.join(PAGE), text.as_bytes())
            .with_context(|| format!("writing {PAGE}"))?;
        println!("coverage: wrote {PAGE}");
        return Ok(());
    }
    let file = root.join(PAGE);
    let problem = if file.is_file() {
        let committed = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {PAGE}"))?
            .replace("\r\n", "\n");
        (committed != text).then(|| format!("{PAGE} does not match what the inputs produce"))
    } else {
        Some(format!("{PAGE} does not exist"))
    };
    if let Some(problem) = problem {
        eprintln!("error: {problem}");
        eprintln!(
            "note: the page is written from rules/**/rule.yaml and their tests/, rules/unconfronted.csv, rules/known-fps.csv, rules/ages/, rules/measured.csv and the collector list; a change to any of them changes the page",
        );
        bail!("coverage: {PAGE} is out of date — run `{COMMAND}` and commit the result");
    }
    println!("coverage: {PAGE} matches the inputs");
    Ok(())
}

/// The whole page, rendered from the inputs under `root`.
pub(crate) fn render(root: &Path) -> anyhow::Result<String> {
    Ok(page::page(&build(root)?))
}

/// The inputs the readers return, checked together so that every problem is reported at once.
struct Inputs {
    /// Every rule id in the bundle.
    rule_ids: BTreeSet<String>,
    /// The `known-fps.csv` rows that parsed.
    known_fps: Vec<check_baseline::KnownFp>,
    /// The `unconfronted.csv` rows that parsed.
    unconfronted: Vec<check_baseline::Unconfronted>,
    /// The `measured.csv` rows that passed every check.
    ledger: Vec<Measured>,
}

/// Loads the rules bundle the product ships, read from the tree as `rules-reference` reads it.
fn load_bundle(root: &Path) -> anyhow::Result<Bundle> {
    let json = collect_bundle_json(&root.join("rules")).context("reading the rules directory")?;
    let bundle = match Bundle::from_bundle_json(&json) {
        Ok(bundle) => bundle,
        Err(BundleError::Invalid(problems)) => bail!(
            "coverage: the rules bundle does not load ({} problem(s)); `cargo xtask check-rules` names them",
            problems.len()
        ),
        Err(error) => bail!("coverage: {error}"),
    };
    Ok(bundle)
}

/// Reads the inputs the readers own, and stops with every problem they report.
fn read_inputs(root: &Path, bundle: &Bundle) -> anyhow::Result<Inputs> {
    let collector_ids: BTreeSet<String> = rongroi_collectors::all()
        .iter()
        .map(|collector| collector.id().to_owned())
        .collect();
    let rule_ids: BTreeSet<String> = bundle
        .rules()
        .iter()
        .map(|sourced| sourced.rule.id.clone())
        .collect();

    let mut problems = Vec::new();
    let known_fps = check_baseline::read_known_fps(root, &mut problems)?;
    let unconfronted = check_baseline::read_unconfronted(root, &mut problems)?;
    let (ledger, ledger_problems) = measured::read(root, &rule_ids, &collector_ids)?;
    problems.extend(ledger_problems);
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("error: {problem}");
        }
        bail!("coverage: {} problem(s) in the inputs; no table is written", problems.len());
    }

    Ok(Inputs {
        rule_ids,
        known_fps,
        unconfronted,
        ledger,
    })
}

/// One row per rule, sorted by collector, then rule directory.
fn rule_rows(root: &Path, bundle: &Bundle, inputs: &Inputs) -> anyhow::Result<Vec<RuleRow>> {
    let ages = bundle.ages();
    let retention = |collector: &str| {
        match ages.iter().find(|age| age.text.collector == collector) {
            Some(age) if age.text.documented => Retention::Documented,
            Some(_) => Retention::Stated,
            None => Retention::None,
        }
    };

    let mut rows = Vec::new();
    for sourced in bundle.rules() {
        let rule = &sourced.rule;
        let dir = rule_dir(&sourced.path);
        let base = root.join("rules").join(&dir);
        let seen_found: BTreeSet<String> = inputs
            .ledger
            .iter()
            .filter(|row| row.subject == rule.id && row.seen == Seen::Found)
            .map(|row| format!("{} {}", row.machine, row.os_build))
            .collect();
        let measured_on: BTreeSet<String> = inputs
            .ledger
            .iter()
            .filter(|row| row.subject == rule.collector && is_measurement(row))
            .map(|row| format!("{} {} {}", row.os_build, row.edition.code(), row.arch.code()))
            .collect();
        rows.push(RuleRow {
            dir,
            collector: rule.collector.clone(),
            role: rule.role.as_str(),
            strength: rule.strength.as_str(),
            status: status_code(rule.status),
            positive: count_fixtures(&base.join("tests").join("positive"))?,
            negative: count_fixtures(&base.join("tests").join("negative"))?,
            known_fp: inputs.known_fps.iter().any(|row| row.rule_id == rule.id),
            unconfronted: inputs.unconfronted.iter().any(|row| row.rule_id == rule.id),
            retention: retention(rule.collector.as_str()),
            seen_found: seen_found.into_iter().collect(),
            measured_on: measured_on.into_iter().collect(),
        });
    }
    rows.sort_by_key(|row| (row.collector.clone(), row.dir.clone()));
    Ok(rows)
}

/// One row per distinct collector of a bundle rule, sorted by id.
fn collector_rows(bundle: &Bundle, ledger: &[Measured]) -> Vec<CollectorRow> {
    let ids: BTreeSet<&str> = bundle
        .rules()
        .iter()
        .map(|sourced| sourced.rule.collector.as_str())
        .collect();
    ids.into_iter()
        .map(|id| collector_row(id, ledger, bundle))
        .collect()
}

/// The rows that name a bundle rule, oldest `added` first, then rule directory. A row naming no
/// bundle rule has no directory to show; `check-baseline` reports it.
fn unconfronted_gaps(
    bundle: &Bundle,
    rows: &[check_baseline::Unconfronted],
) -> Vec<UnconfrontedGap> {
    let mut gaps: Vec<UnconfrontedGap> = rows
        .iter()
        .filter_map(|row| {
            let sourced = bundle
                .rules()
                .iter()
                .find(|sourced| sourced.rule.id == row.rule_id)?;
            Some(UnconfrontedGap {
                dir: rule_dir(&sourced.path),
                added: row.added.clone(),
                resolved_when: row.resolved_when.clone(),
            })
        })
        .collect();
    gaps.sort_by_key(|gap| (gap.added.clone(), gap.dir.clone()));
    gaps
}

/// Builds the model from the inputs under `root`. Any reader problem stops it first.
pub(crate) fn build(root: &Path) -> anyhow::Result<Table> {
    let bundle = load_bundle(root)?;
    let inputs = read_inputs(root, &bundle)?;
    let rows = rule_rows(root, &bundle, &inputs)?;
    let collectors = collector_rows(&bundle, &inputs.ledger);
    let unconfronted = unconfronted_gaps(&bundle, &inputs.unconfronted);
    let ledger_rule_rows = inputs
        .ledger
        .iter()
        .filter(|row| inputs.rule_ids.contains(&row.subject))
        .count();
    let ledger_collector_rows = inputs.ledger.len() - ledger_rule_rows;
    Ok(Table {
        rows,
        collectors,
        unconfronted,
        ledger_collector_rows,
        ledger_rule_rows,
    })
}

/// The model of one collector, from the ledger rows that say it ran and what it produced.
fn collector_row(id: &str, ledger: &[Measured], bundle: &Bundle) -> CollectorRow {
    let measured: Vec<&Measured> = ledger
        .iter()
        .filter(|row| row.subject == id && is_measurement(row))
        .collect();
    CollectorRow {
        id: id.to_owned(),
        builds: measured.iter().map(|row| row.os_build.clone()).collect(),
        client: measured.iter().any(|row| row.edition == Edition::Client),
        windows10: measured.iter().any(|row| {
            leading_build(&row.os_build).is_some_and(|build| build < WINDOWS_11_FIRST_BUILD)
        }),
        limited: measured.iter().any(|row| row.token == Token::Limited),
        has_ages: bundle.ages().iter().any(|age| age.text.collector == id),
    }
}

/// Whether a collector row says the collector ran and produced something, or ran and found nothing.
fn is_measurement(row: &Measured) -> bool {
    matches!(row.seen, Seen::Observations | Seen::None)
}

/// The rule's path without its file name: `posture/boot/x` for `posture/boot/x/rule.yaml`.
fn rule_dir(path: &str) -> String {
    path.strip_suffix("/rule.yaml").unwrap_or(path).to_owned()
}

/// The first number of a build, such as `26100` for `26100.4061`.
fn leading_build(os_build: &str) -> Option<u32> {
    os_build.split('.').next()?.parse().ok()
}

/// The status as `rule.yaml` spells it.
fn status_code(status: Status) -> &'static str {
    match status {
        Status::Experimental => "experimental",
        Status::Test => "test",
        Status::Stable => "stable",
        Status::Deprecated => "deprecated",
    }
}

/// The number of `*.json` fixtures in `dir`; a directory that does not exist has none.
fn count_fixtures(dir: &Path) -> anyhow::Result<usize> {
    if !dir.is_dir() {
        return Ok(0);
    }
    let mut count = 0;
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "json") {
            count += 1;
        }
    }
    Ok(count)
}

mod page;
#[cfg(test)]
mod tests;
