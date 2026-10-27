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
//! Besides rule states, a scenario can expect facts about `game_windows` candidates (each listed fact is
//! checked against the scan's candidate of that name) and whether the clock changed during the scan. Those
//! checks print no ledger row. `full: true` is read only by `lab/replay.sh`, which asks for a full scan.
//!
//! A problem with an input stops the command before any line is printed. A failed check prints its line,
//! then the command returns an error, and no ledger row is printed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use rongroi_core::bundle::{Bundle, BundleError};
use rongroi_core::source_tree::collect_bundle_json;
use serde::Deserialize;
use serde_json::{Map, Value};

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

/// A scenario's `expect.yaml`: the rules that must read `found`, the neighbours that must not, the
/// `game_windows` candidates whose facts must hold, and whether the clock must have changed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Expect {
    /// Rule ids that must read `found`. At least one of `found`, `game_windows` or `clock_changed` is
    /// required.
    pub(crate) found: Vec<String>,
    /// Neighbouring rule ids that must read `not_found`.
    #[serde(default)]
    pub(crate) not_found: Vec<String>,
    /// Read only by the driver script, which restarts the machine once between setup and scan.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) restart: bool,
    /// Read only by the driver script, which makes the scan a full scan and answers its consent question.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) full: bool,
    /// `game_windows` candidates whose listed facts must hold in the scan.
    #[serde(default)]
    pub(crate) game_windows: Vec<CandidateExpect>,
    /// Whether the clock must have changed during the scan (`true`), or must not have (`false`).
    #[serde(default)]
    pub(crate) clock_changed: Option<bool>,
}

/// One `game_windows` entry of an `expect.yaml`: a candidate's name and the facts it must hold.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidateExpect {
    /// The candidate's file name, matched against the scan's candidate names without regard to ASCII case.
    pub(crate) name: String,
    /// Fact key (`t1`…`t4`, `i1`…`i5`, `l1`) to the value it must read: `true`, `false`, `not_known`, or
    /// `not_known:<reason>`.
    pub(crate) facts: BTreeMap<String, String>,
}

/// The fact keys a scan candidate and an `expect.yaml` may use.
const FACT_KEYS: [&str; 10] = ["t1", "t2", "t3", "t4", "i1", "i2", "i3", "i4", "i5", "l1"];

/// A parsed scan: the header fields the checks use, and each rule's state as the scan reads it.
#[derive(Debug)]
pub(crate) struct Scan {
    /// `header.os_build`, such as `26300`.
    pub(crate) os_build: String,
    /// `header.elevated`: whether the scan ran with an elevated token.
    pub(crate) elevated: bool,
    /// Rule id to state (`found`, `not_found` or `unmeasured`).
    states: BTreeMap<String, String>,
    /// The game-window view, or `None` when the scan has none (`game_windows` absent or `null`).
    pub(crate) game_windows: Option<GameWindowsSeen>,
    /// How many clock changes the scan recorded; zero when it has no game-window view.
    pub(crate) clock_changes: usize,
}

impl Scan {
    /// The state the scan reads for `id`; a rule missing from `evidence` reads `absent`.
    pub(crate) fn state(&self, id: &str) -> &str {
        self.states.get(id).map_or("absent", String::as_str)
    }
}

/// The candidates of a scan's game-window view, each with its facts read as strings.
#[derive(Debug)]
pub(crate) struct GameWindowsSeen {
    /// Every candidate the scan lists, in scan order.
    pub(crate) candidates: Vec<SeenCandidate>,
}

/// One candidate of the game-window view: its name and the facts the scan read for it.
#[derive(Debug)]
pub(crate) struct SeenCandidate {
    /// The candidate's name as the scan writes it.
    pub(crate) name: String,
    /// Fact key to `true`, `false` or `not_known:<reason>`; a key the scan did not write is absent.
    facts: BTreeMap<String, String>,
}

impl SeenCandidate {
    /// The value the scan read for fact `key`, or `absent` when the scan did not write it.
    fn fact(&self, key: &str) -> &str {
        self.facts.get(key).map_or("absent", String::as_str)
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
    /// Absent or `null` when the scan has no game-window view; other keys are ignored.
    #[serde(default)]
    game_windows: Option<RawGameWindows>,
}

#[derive(Deserialize)]
struct RawGameWindows {
    #[serde(default)]
    candidates: Vec<Map<String, Value>>,
    #[serde(default)]
    clock: Option<RawClock>,
}

#[derive(Deserialize)]
struct RawClock {
    #[serde(default)]
    changes: Vec<Value>,
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
    let clock_changes = raw
        .game_windows
        .as_ref()
        .and_then(|view| view.clock.as_ref())
        .map_or(0, |clock| clock.changes.len());
    let game_windows = raw.game_windows.map(read_game_windows).transpose()?;
    Ok(Scan {
        os_build: raw.header.os_build,
        elevated: raw.header.elevated,
        states,
        game_windows,
        clock_changes,
    })
}

/// Reads the game-window view. Only the fact keys of each candidate are read; every other key is ignored.
fn read_game_windows(raw: RawGameWindows) -> anyhow::Result<GameWindowsSeen> {
    let mut candidates = Vec::new();
    for candidate in raw.candidates {
        let name = candidate
            .get("name")
            .and_then(Value::as_str)
            .context("a game_windows candidate in the scan has no name")?
            .to_owned();
        let mut facts = BTreeMap::new();
        for (key, value) in &candidate {
            if FACT_KEYS.contains(&key.as_str()) {
                facts.insert(key.clone(), read_fact(&name, key, value)?);
            }
        }
        candidates.push(SeenCandidate { name, facts });
    }
    Ok(GameWindowsSeen { candidates })
}

/// Reads one fact as `true`, `false` or `not_known:<reason>`. Any other shape is an error naming the
/// candidate and the key.
fn read_fact(name: &str, key: &str, value: &Value) -> anyhow::Result<String> {
    let fact = value
        .get("fact")
        .and_then(Value::as_str)
        .ok_or_else(|| fact_shape(name, key))?;
    match fact {
        "true" | "false" => Ok(fact.to_owned()),
        "not_known" => {
            let reason = value
                .get("reason")
                .and_then(|reason| reason.get("reason"))
                .and_then(Value::as_str)
                .ok_or_else(|| fact_shape(name, key))?;
            Ok(format!("not_known:{reason}"))
        }
        _ => Err(fact_shape(name, key)),
    }
}

fn fact_shape(name: &str, key: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "lab-check: scan candidate {name} has fact {key} in a shape this check does not read"
    )
}

/// Refuses an `expect` that expects nothing, an id listed twice, an id that is not a rule in `known`, a
/// candidate listed twice or with no name, a fact key outside [`FACT_KEYS`], or a fact value the scan
/// cannot hold. Every problem is reported at once.
pub(crate) fn validate_expect(expect: &Expect, known: &BTreeSet<String>) -> anyhow::Result<()> {
    let nothing_expected =
        expect.found.is_empty() && expect.game_windows.is_empty() && expect.clock_changed.is_none();
    if nothing_expected {
        bail!(
            "lab-check: expect.yaml expects nothing: no `found` rule, no `game_windows` candidate and no `clock_changed`; at least one is required"
        );
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
    // Candidate names match the scan's without regard to ASCII case,
    // so the duplicate test folds case too.
    let mut names = BTreeSet::new();
    for candidate in &expect.game_windows {
        if candidate.name.is_empty() {
            problems.push("a game_windows candidate has an empty name".to_owned());
        } else if !names.insert(candidate.name.to_ascii_lowercase()) {
            problems.push(format!(
                "game_windows candidate {} is listed more than once (names match without regard to ASCII case)",
                candidate.name
            ));
        }
        for (key, value) in &candidate.facts {
            if !FACT_KEYS.contains(&key.as_str()) {
                problems.push(format!(
                    "{}: fact key {key} is not one of t1-t4, i1-i5, l1",
                    candidate.name
                ));
            }
            if !is_fact_value(value) {
                problems.push(format!(
                    "{}: fact {key} has value `{value}`; use true, false, not_known or not_known:<reason>",
                    candidate.name
                ));
            }
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
/// `not_found`, and with a control, no `found` id may read `found` there. Then each `game_windows` entry
/// is checked against the scan's game-window view, and `clock_changed` against the scan's clock changes.
/// The control scan is not consulted for the game-window or clock checks.
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
    for candidate in &expect.game_windows {
        check_candidate(&mut report, candidate, scan.game_windows.as_ref());
    }
    if let Some(want) = expect.clock_changed {
        let pass = (scan.clock_changes > 0) == want;
        let tail = if pass {
            String::new()
        } else {
            format!(" read {}", scan.clock_changes)
        };
        report.push(pass, "clock", "changes", &tail);
    }
    report
}

/// Checks one `game_windows` entry: one line per listed fact, or one line when the scan has no view or
/// no candidate of that name. Two candidates may share a name; the one that holds every listed fact
/// supplies the values, and if none does, the first one does.
fn check_candidate(report: &mut Report, expect: &CandidateExpect, view: Option<&GameWindowsSeen>) {
    let Some(view) = view else {
        report.push(
            false,
            "view",
            &expect.name,
            " no game-window view in the scan",
        );
        return;
    };
    let matching: Vec<&SeenCandidate> = view
        .candidates
        .iter()
        .filter(|candidate| candidate.name.eq_ignore_ascii_case(&expect.name))
        .collect();
    let Some(&first) = matching.first() else {
        report.push(false, "candidate", &expect.name, " not a candidate");
        return;
    };
    let holds_all = |candidate: &SeenCandidate| {
        expect
            .facts
            .iter()
            .all(|(key, want)| fact_holds(want, candidate.fact(key)))
    };
    let chosen = matching
        .iter()
        .copied()
        .find(|&candidate| holds_all(candidate))
        .unwrap_or(first);
    for (key, want) in &expect.facts {
        let actual = chosen.fact(key);
        let pass = fact_holds(want, actual);
        let tail = if pass {
            String::new()
        } else {
            format!(" read {actual}")
        };
        report.push(pass, "fact", &format!("{} {key}", expect.name), &tail);
    }
}

/// Whether the scan's `actual` fact satisfies the expected `want`: equal, or `not_known` matching any
/// reason.
fn fact_holds(want: &str, actual: &str) -> bool {
    actual == want || (want == "not_known" && actual.starts_with("not_known"))
}

/// Whether `text` is a fact value an `expect.yaml` may name: `true`, `false`, `not_known`, or
/// `not_known:<reason>` with a reason of lowercase letters, digits and underscores (`^[a-z0-9_]+$`).
fn is_fact_value(text: &str) -> bool {
    match text {
        "true" | "false" | "not_known" => true,
        _ => text.strip_prefix("not_known:").is_some_and(|reason| {
            !reason.is_empty()
                && reason
                    .bytes()
                    .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
        }),
    }
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
