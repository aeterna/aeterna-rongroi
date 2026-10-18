// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask lab-check`: checks one lab-replay scan against a scenario's `expect.yaml` (ADR 0076 §1, §4).
//!
//! The scan is the JSON `rongroi.exe scan --json` writes on the lab machine. This module reads the three
//! files and the rules bundle, then calls the pure functions [`check`], [`ledger_rows`] and
//! [`validate_expect`], which the tests call with parsed values. Nothing here reads the clock, the network
//! or a machine, so the same files give the same output.
//!
//! A problem with an input stops the command before any line is printed. A failed check prints its line,
//! then the command returns an error, and no ledger row is printed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use rongroi_core::bundle::{Bundle, BundleError};
use rongroi_core::source_tree::collect_bundle_json;
use serde::Deserialize;

#[derive(clap::Args)]
pub struct Args {
    /// The scenario's `expect.yaml`.
    #[arg(long)]
    expect: PathBuf,
    /// The scan JSON `rongroi.exe scan --json` wrote on the lab machine.
    #[arg(long)]
    scan: PathBuf,
    /// The control scan JSON, from a fresh overlay with no `setup.ps1`.
    #[arg(long)]
    control: Option<PathBuf>,
    /// Ledger evidence text; with every check passing, prints one `measured.csv` row per expected rule.
    #[arg(long, requires = "date")]
    evidence: Option<String>,
    /// Run date for the ledger rows, `YYYY-MM-DD`; required with `--evidence`.
    #[arg(long, requires = "evidence")]
    date: Option<String>,
}

/// A scenario's `expect.yaml`: the rules that must read `found`, and the neighbours that must not.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Expect {
    /// Rule ids that must read `found`. At least one.
    pub(crate) found: Vec<String>,
    /// Neighbouring rule ids that must read `not_found`.
    #[serde(default)]
    pub(crate) not_found: Vec<String>,
    /// Read only by the driver script, which restarts the machine once between setup and scan.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) restart: bool,
}

/// A parsed scan: the header fields the checks use, and each rule's state as the scan reads it.
#[derive(Debug)]
pub(crate) struct Scan {
    /// `header.os_build`, such as `26300`.
    pub(crate) os_build: String,
    /// `header.elevated`: whether the scan ran with an elevated token.
    pub(crate) elevated: bool,
    /// Rule id to state (`found`, `not_found` or `unmeasured`).
    states: BTreeMap<String, String>,
}

impl Scan {
    /// The state the scan reads for `id`; a rule missing from `evidence` reads `absent`.
    pub(crate) fn state(&self, id: &str) -> &str {
        self.states.get(id).map_or("absent", String::as_str)
    }
}

/// The result of [`check`]: one line per check, in output order, and how many passed or failed.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Report {
    /// One line per check, in output order.
    pub(crate) lines: Vec<String>,
    /// Checks that passed.
    pub(crate) ok: usize,
    /// Checks that failed.
    pub(crate) failed: usize,
}

impl Report {
    fn push(&mut self, pass: bool, kind: &str, id: &str, tail: &str) {
        let tag = if pass { "ok    " } else { "FAIL  " };
        if pass {
            self.ok += 1;
        } else {
            self.failed += 1;
        }
        self.lines.push(format!("{tag}{kind:<11}{id}{tail}"));
    }
}

#[derive(Deserialize)]
struct RawScan {
    header: Header,
    evidence: Vec<Evidence>,
}

#[derive(Deserialize)]
struct Header {
    os_build: String,
    elevated: bool,
}

#[derive(Deserialize)]
struct Evidence {
    rule_id: String,
    state: String,
}

pub fn run(root: &Path, args: &Args) -> anyhow::Result<()> {
    if let Some(date) = args.date.as_deref()
        && !is_date(date)
    {
        bail!("lab-check: --date must be YYYY-MM-DD, got `{date}`");
    }
    let known = rule_ids(root)?;
    let expect = parse_expect(&read(&args.expect)?)?;
    validate_expect(&expect, &known)?;
    let scan = parse_scan(&read(&args.scan)?)?;
    let control = match args.control.as_deref() {
        Some(path) => Some(parse_scan(&read(path)?)?),
        None => None,
    };

    let report = check(&expect, &scan, control.as_ref());
    for line in &report.lines {
        println!("{line}");
    }
    println!("lab-check: {} ok, {} failed", report.ok, report.failed);
    if report.failed > 0 {
        bail!(
            "lab-check: {} check(s) failed; no ledger row is written",
            report.failed
        );
    }
    if let (Some(evidence), Some(date)) = (args.evidence.as_deref(), args.date.as_deref()) {
        for row in ledger_rows(&expect, &scan, evidence, date) {
            println!("{row}");
        }
    }
    Ok(())
}

/// Parses `expect.yaml`. An unknown key is an error.
pub(crate) fn parse_expect(text: &str) -> anyhow::Result<Expect> {
    serde_saphyr::from_str::<Expect>(strip_bom(text)).context("parsing expect.yaml")
}

/// Parses a scan JSON, after stripping a UTF-8 byte-order mark. A rule listed twice is an error.
pub(crate) fn parse_scan(text: &str) -> anyhow::Result<Scan> {
    let raw: RawScan = serde_json::from_str(strip_bom(text)).context("parsing the scan JSON")?;
    let mut states = BTreeMap::new();
    for row in raw.evidence {
        if states.insert(row.rule_id.clone(), row.state).is_some() {
            bail!("lab-check: the scan lists rule {} twice", row.rule_id);
        }
    }
    Ok(Scan {
        os_build: raw.header.os_build,
        elevated: raw.header.elevated,
        states,
    })
}

/// Refuses an `expect` with no `found` id, an id listed twice, or an id that is not a rule in `known`.
/// Every problem is reported at once.
pub(crate) fn validate_expect(expect: &Expect, known: &BTreeSet<String>) -> anyhow::Result<()> {
    if expect.found.is_empty() {
        bail!("lab-check: expect.yaml names no `found` rule; at least one is required");
    }
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    for id in expect.found.iter().chain(&expect.not_found) {
        if !seen.insert(id.as_str()) {
            problems.push(format!("{id} is listed more than once"));
        }
        if !known.contains(id) {
            problems.push(format!("{id} is not a rule id in rules/"));
        }
    }
    if !problems.is_empty() {
        bail!(
            "lab-check: expect.yaml refused:\n  {}",
            problems.join("\n  ")
        );
    }
    Ok(())
}

/// Checks the scan against `expect`: every `found` id must read `found`, every `not_found` id must read
/// `not_found`, and with a control, no `found` id may read `found` there.
pub(crate) fn check(expect: &Expect, scan: &Scan, control: Option<&Scan>) -> Report {
    let mut report = Report::default();
    for id in &expect.found {
        check_state(&mut report, "found", id, scan.state(id), "found");
        if let Some(control) = control {
            let pass = control.state(id) != "found";
            let tail = if pass {
                ""
            } else {
                " read found with no scenario"
            };
            report.push(pass, "control", id, tail);
        }
    }
    for id in &expect.not_found {
        check_state(&mut report, "not_found", id, scan.state(id), "not_found");
    }
    report
}

/// The `measured.csv` rows for a passing scan: one per expected id, `found` then `not_found`, in the
/// column order of `rules/measured.csv`.
pub(crate) fn ledger_rows(expect: &Expect, scan: &Scan, evidence: &str, date: &str) -> Vec<String> {
    let token = if scan.elevated { "elevated" } else { "limited" };
    let evidence = csv_field(evidence);
    let os_build = &scan.os_build;
    expect
        .found
        .iter()
        .map(|id| (id, "found"))
        .chain(expect.not_found.iter().map(|id| (id, "not_found")))
        .map(|(id, seen)| {
            format!("{id},lab-vm-arm64,{os_build},client,arm64,{token},{seen},{evidence},{date}")
        })
        .collect()
}

/// Whether `text` is a real calendar date written `YYYY-MM-DD`.
pub(crate) fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let num = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = text.get(range)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (Some(year), Some(month), Some(day)) = (num(0..4), num(5..7), num(8..10)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

fn check_state(report: &mut Report, kind: &str, id: &str, state: &str, want: &str) {
    let pass = state == want;
    let tail = if pass {
        String::new()
    } else {
        format!(" read {state}")
    };
    report.push(pass, kind, id, &tail);
}

/// Quotes a CSV field that contains a comma or a double quote, doubling any quote inside it.
fn csv_field(text: &str) -> String {
    if text.contains([',', '"']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_owned()
    }
}

fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

fn read(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// The ids of every rule in the bundle under `root/rules`.
fn rule_ids(root: &Path) -> anyhow::Result<BTreeSet<String>> {
    let bundle = load_bundle(root)?;
    Ok(bundle
        .rules()
        .iter()
        .map(|sourced| sourced.rule.id.clone())
        .collect())
}

/// Loads the rules bundle the product ships, read from the tree as `coverage` reads it.
fn load_bundle(root: &Path) -> anyhow::Result<Bundle> {
    let json = collect_bundle_json(&root.join("rules")).context("reading the rules directory")?;
    match Bundle::from_bundle_json(&json) {
        Ok(bundle) => Ok(bundle),
        Err(BundleError::Invalid(problems)) => bail!(
            "lab-check: the rules bundle does not load ({} problem(s)); `cargo xtask check-rules` names them",
            problems.len()
        ),
        Err(error) => bail!("lab-check: {error}"),
    }
}

#[cfg(test)]
mod tests;
