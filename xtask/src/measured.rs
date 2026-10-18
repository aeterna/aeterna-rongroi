// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The measurement ledger of ADR 0074 §1: `rules/measured.csv`, one row per thing seen on one machine
//! at one time. States and builds only, never a value a collector read.
//!
//! [`read`] returns the rows that pass every check and one problem per failed field of the rest, as
//! `rules/measured.csv:<line>: <message>`. An absent file is no rows and no problem. Nothing here reads
//! the clock or a machine.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::path::Path;

use jiff::civil::Date;

use crate::check_baseline::parse_csv_line;

/// Where the ledger lives, relative to the repository root.
pub(crate) const MEASURED: &str = "rules/measured.csv";
/// The header line, which must be the first line that is neither blank nor a comment.
pub(crate) const HEADER: &str = "subject,machine,os_build,edition,arch,token,seen,evidence,date";

/// The edition of Windows a row was measured on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Edition {
    Client,
    Server,
}

impl Edition {
    /// The spelling this value has in the CSV.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// The processor architecture a row was measured on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arch {
    X64,
    Arm64,
}

impl Arch {
    /// The spelling this value has in the CSV.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
        }
    }
}

/// Whether the collector ran elevated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Token {
    Elevated,
    Limited,
}

impl Token {
    /// The spelling this value has in the CSV.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Elevated => "elevated",
            Self::Limited => "limited",
        }
    }
}

/// What was seen. A collector row takes `Observations`, `None` or `Unmeasured`; a rule row takes
/// `Found`, `NotFound` or `Unmeasured`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Seen {
    Observations,
    None,
    Found,
    NotFound,
    /// Not measured here, for the reason given (never empty).
    Unmeasured(String),
}

impl Seen {
    /// The keyword this value has in the CSV. `Unmeasured` gives `unmeasured`; its reason follows the
    /// colon in the file.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Observations => "observations",
            Self::None => "none",
            Self::Found => "found",
            Self::NotFound => "not_found",
            Self::Unmeasured(_) => "unmeasured",
        }
    }
}

/// One validated row of `rules/measured.csv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Measured {
    /// 1-based line in the file.
    pub(crate) line: usize,
    /// A rule id or a collector name.
    pub(crate) subject: String,
    /// `owner-pc`, `lab-vm-arm64`, or `gha-<label>`.
    pub(crate) machine: String,
    /// Such as `26100` or `26100.4061`.
    pub(crate) os_build: String,
    pub(crate) edition: Edition,
    pub(crate) arch: Arch,
    pub(crate) token: Token,
    pub(crate) seen: Seen,
    /// Never empty.
    pub(crate) evidence: String,
    pub(crate) date: Date,
}

/// Whether a subject is a rule or a collector. It decides which `seen` values are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Rule,
    Collector,
}

/// Reads `rules/measured.csv` under `root`.
///
/// Returns the rows that pass every check, and a problem for every field that fails one. A row with a
/// problem is not returned. A row that repeats an earlier row in all nine fields is a problem naming
/// the earlier line.
pub(crate) fn read(
    root: &Path,
    rule_ids: &BTreeSet<String>,
    collectors: &BTreeSet<String>,
) -> anyhow::Result<(Vec<Measured>, Vec<String>)> {
    let path = root.join(MEASURED);
    if !path.is_file() {
        return Ok((Vec::new(), Vec::new()));
    }
    let text = std::fs::read_to_string(&path)?;
    let mut rows = Vec::new();
    let mut problems = Vec::new();
    let mut header_seen = false;
    // Every data row so far, by its fields, so that a repeat can name the line it repeats.
    let mut earlier: HashMap<Vec<String>, usize> = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !header_seen {
            header_seen = true;
            if trimmed != HEADER {
                problems.push(problem(
                    line_number,
                    format!("the header must be `{HEADER}`"),
                ));
            }
            continue;
        }
        let fields = parse_csv_line(trimmed);
        if let Some(&first) = earlier.get(&fields) {
            problems.push(problem(
                line_number,
                format!("repeats the row on line {first}"),
            ));
            continue;
        }
        earlier.insert(fields.clone(), line_number);
        match check_row(line_number, &fields, rule_ids, collectors) {
            Ok(row) => rows.push(row),
            Err(mut found) => problems.append(&mut found),
        }
    }
    if !header_seen {
        problems.push(format!("{MEASURED}: the header `{HEADER}` is missing"));
    }
    Ok((rows, problems))
}

/// Checks every field of one data row. Every failed field is reported, and the row is returned only
/// when none failed.
fn check_row(
    line: usize,
    fields: &[String],
    rule_ids: &BTreeSet<String>,
    collectors: &BTreeSet<String>,
) -> Result<Measured, Vec<String>> {
    let [subject, machine, os_build, edition, arch, token, seen, evidence, date] = fields else {
        return Err(vec![problem(
            line,
            format!("expected the 9 fields of `{HEADER}`, found {}", fields.len()),
        )]);
    };
    let mut problems = Vec::new();
    let kind = if rule_ids.contains(subject) {
        Some(Kind::Rule)
    } else if collectors.contains(subject) {
        Some(Kind::Collector)
    } else {
        problems.push(problem(
            line,
            format!("`subject` `{subject}` is neither a rule in the bundle nor a collector"),
        ));
        None
    };
    let machine = keep(line, parse_machine(machine), &mut problems);
    let os_build = keep(line, parse_os_build(os_build), &mut problems);
    let edition = choose(
        "edition",
        edition,
        [("client", Edition::Client), ("server", Edition::Server)],
    );
    let edition = keep(line, edition, &mut problems);
    let arch = choose("arch", arch, [("x64", Arch::X64), ("arm64", Arch::Arm64)]);
    let arch = keep(line, arch, &mut problems);
    let token = choose(
        "token",
        token,
        [("elevated", Token::Elevated), ("limited", Token::Limited)],
    );
    let token = keep(line, token, &mut problems);
    let seen = keep(line, parse_seen(seen, kind), &mut problems);
    let evidence = keep(line, parse_evidence(evidence), &mut problems);
    let date = keep(line, parse_date(date), &mut problems);
    if !problems.is_empty() {
        return Err(problems);
    }
    match (machine, os_build, edition, arch, token, seen, evidence, date) {
        (
            Some(machine),
            Some(os_build),
            Some(edition),
            Some(arch),
            Some(token),
            Some(seen),
            Some(evidence),
            Some(date),
        ) => Ok(Measured {
            line,
            subject: subject.clone(),
            machine,
            os_build,
            edition,
            arch,
            token,
            seen,
            evidence,
            date,
        }),
        // Every field parsed when no problem was recorded, so this arm is not reached; it returns an
        // error rather than panicking if that ever changes.
        _ => Err(vec![problem(line, "a field passed without a value")]),
    }
}

/// `<file>:<line>: <message>`, the form every problem in this file takes.
fn problem(line: usize, message: impl fmt::Display) -> String {
    format!("{MEASURED}:{line}: {message}")
}

/// Keeps a parsed field, or records its problem and keeps nothing.
fn keep<T>(line: usize, result: Result<T, String>, problems: &mut Vec<String>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(message) => {
            problems.push(problem(line, message));
            None
        }
    }
}

/// `owner-pc`, `lab-vm-arm64`, or `gha-<label>`.
fn parse_machine(text: &str) -> Result<String, String> {
    let valid = matches!(text, "owner-pc" | "lab-vm-arm64")
        || text.strip_prefix("gha-").is_some_and(valid_label);
    if valid {
        Ok(text.to_owned())
    } else {
        Err(format!(
            "`machine` `{text}` must be `owner-pc`, `lab-vm-arm64`, or `gha-<label>`, where the label is lowercase letters, digits and `-`, and does not start or end with `-`"
        ))
    }
}

/// A non-empty label of lowercase letters, digits and `-`, not starting or ending with `-`.
fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Digits, optionally a `.` and digits, with no part that begins with a zero.
fn parse_os_build(text: &str) -> Result<String, String> {
    let parts: Vec<&str> = text.split('.').collect();
    let valid = (1..=2).contains(&parts.len())
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && !part.starts_with('0')
        });
    if valid {
        Ok(text.to_owned())
    } else {
        Err(format!(
            "`os_build` `{text}` must be digits, optionally a `.` and digits, with no leading zero (for example `26100` or `26100.4061`)"
        ))
    }
}

/// One of two spellings, each mapped to its value. `field` names the column in the message.
fn choose<T>(
    field: &str,
    text: &str,
    [(a, first), (b, second)]: [(&str, T); 2],
) -> Result<T, String> {
    if text == a {
        Ok(first)
    } else if text == b {
        Ok(second)
    } else {
        Err(format!("`{field}` `{text}` must be `{a}` or `{b}`"))
    }
}

/// `seen` for a subject of the given kind. With no kind (the subject is unknown, which is already a
/// problem) the spellings of both kinds are accepted, so this field is still checked for shape.
fn parse_seen(text: &str, kind: Option<Kind>) -> Result<Seen, String> {
    if let Some(reason) = text.strip_prefix("unmeasured:") {
        let reason = reason.trim();
        return if reason.is_empty() {
            Err("`seen` `unmeasured:` needs a reason after the colon".to_owned())
        } else {
            Ok(Seen::Unmeasured(reason.to_owned()))
        };
    }
    let collector = kind != Some(Kind::Rule);
    let rule = kind != Some(Kind::Collector);
    match text {
        "observations" if collector => Ok(Seen::Observations),
        "none" if collector => Ok(Seen::None),
        "found" if rule => Ok(Seen::Found),
        "not_found" if rule => Ok(Seen::NotFound),
        _ => Err(match kind {
            Some(Kind::Rule) => format!(
                "`seen` `{text}` is not allowed on a rule: a rule takes `found`, `not_found`, or `unmeasured:<reason>`"
            ),
            Some(Kind::Collector) => format!(
                "`seen` `{text}` is not allowed on a collector: a collector takes `observations`, `none`, or `unmeasured:<reason>`"
            ),
            None => format!(
                "`seen` `{text}` must be `observations`, `none`, `found`, `not_found`, or `unmeasured:<reason>`"
            ),
        }),
    }
}

fn parse_evidence(text: &str) -> Result<String, String> {
    if text.trim().is_empty() {
        Err("`evidence` must not be empty: give a CI run id, a path under `docs/`, or the name of a probe result".to_owned())
    } else {
        Ok(text.trim().to_owned())
    }
}

/// A day written `YYYY-MM-DD`. The shape is checked before parsing, so `jiff` cannot accept another.
fn parse_date(text: &str) -> Result<Date, String> {
    let shaped = text.len() == 10
        && text.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        });
    match text.parse::<Date>() {
        Ok(date) if shaped => Ok(date),
        _ => Err(format!("`date` `{text}` must be a day written `YYYY-MM-DD`")),
    }
}

#[cfg(test)]
mod tests;
