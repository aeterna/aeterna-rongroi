// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `rules/certificate-pins.csv`: what is known about each certificate a rule's `allow` names, so that
//! its expiry is visible before it arrives (ADR 0036, amendment of 2026-09-14).
//!
//! An `allow: signer_cert_sha256` entry goes stale for every player at once when the publisher starts
//! signing with a renewed certificate, and nothing in the rule says when that will be. The last date
//! the pinned certificate can sign anything new is its `not_after`, which was measured with it. This
//! module holds that measurement in one place and checks it twice:
//!
//! - **`cargo xtask check-rules`**, on every pull request: every certificate an `allow` names has a row,
//!   every row names a certificate its rule allows, and every value parses. Nothing here reads a clock,
//!   so an ordinary pull request is never red because of a date.
//! - **`cargo xtask check-pin-expiry`**, on a monthly schedule only (`certificate-pins.yml`): fails when
//!   the newest pin of some rule reaches its `not_after` within [`WARN_DAYS`] days.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, bail};
use jiff::Timestamp;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use rongroi_core::bundle::Bundle;

use crate::check_baseline::parse_csv_line;

/// Where the pins are recorded, relative to the repository root.
pub const PINS: &str = "rules/certificate-pins.csv";
/// The columns the file must declare, in this order.
const COLUMNS: [&str; 6] = [
    "rule_id",
    "signer_cert_sha256",
    "subject",
    "not_before",
    "not_after",
    "measured_on",
];
/// How many days before a pinned certificate's `not_after` the scheduled check fails.
///
/// The schedule is monthly, so two runs are at most 31 days apart, and 90 days holds at least two
/// runs — usually three — before the date: one run GitHub drops under load still leaves a warning.
/// The rest is ADR 0036's amendment of 2026-09-14.
pub const WARN_DAYS: i32 = 90;

/// One row of the file.
#[derive(Debug)]
pub struct Pin {
    /// Line in the file, for messages.
    pub line: usize,
    /// The rule whose `allow` names the certificate.
    pub rule_id: String,
    /// SHA-256 of the certificate, as `allow` compares it.
    pub signer_cert_sha256: String,
    /// The certificate's subject, as it was measured.
    pub subject: String,
    /// When the certificate became valid.
    pub not_before: Timestamp,
    /// When the certificate stops being valid.
    pub not_after: Timestamp,
    /// When the row's values were measured.
    pub measured_on: Date,
}

/// Reads the file. Every malformed row is a problem and is left out; an absent file is no rows, which
/// [`check_against_bundle`] then reports if any rule allows a certificate.
pub fn read(root: &Path, problems: &mut Vec<String>) -> anyhow::Result<Vec<Pin>> {
    let path = root.join(PINS);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {PINS}"))?;
    Ok(parse(&text, problems))
}

fn parse(text: &str, problems: &mut Vec<String>) -> Vec<Pin> {
    let header = COLUMNS.join(",");
    let mut pins = Vec::new();
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
            if fields != COLUMNS {
                problems.push(format!(
                    "{PINS}:{line_number}: the first row must be the header `{header}`"
                ));
            }
            continue;
        }
        let [rule_id, cert, subject, not_before, not_after, measured_on] = fields.as_slice() else {
            problems.push(format!(
                "{PINS}:{line_number}: expected the {} fields of `{header}`, found {}",
                COLUMNS.len(),
                fields.len()
            ));
            continue;
        };
        let mut bad = |message: String| problems.push(format!("{PINS}:{line_number}: {message}"));
        let is_digest = cert.len() == 64
            && cert
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !is_digest {
            bad(format!(
                "`signer_cert_sha256` must be 64 lowercase hex characters, as `allow` writes it; found `{cert}`"
            ));
        }
        if subject.trim().is_empty() {
            bad("`subject` must say whose certificate this is, as it was measured".to_owned());
        }
        let not_before = not_before.parse::<Timestamp>().map_err(|error| {
            bad(format!(
                "`not_before` must be an RFC 3339 timestamp such as `2026-07-21T00:00:00Z`: {error}"
            ));
        });
        let not_after = not_after.parse::<Timestamp>().map_err(|error| {
            bad(format!(
                "`not_after` must be an RFC 3339 timestamp such as `2027-09-05T23:59:59Z`: {error}"
            ));
        });
        let measured_on = measured_on.parse::<Date>().map_err(|error| {
            bad(format!(
                "`measured_on` must be a date such as `2026-09-13`: {error}"
            ));
        });
        let (Ok(not_before), Ok(not_after), Ok(measured_on)) = (not_before, not_after, measured_on)
        else {
            continue;
        };
        if not_before >= not_after {
            bad(format!(
                "`not_before` {not_before} is not before `not_after` {not_after}"
            ));
            continue;
        }
        if !is_digest || subject.trim().is_empty() {
            continue;
        }
        pins.push(Pin {
            line: line_number,
            rule_id: rule_id.clone(),
            signer_cert_sha256: cert.clone(),
            subject: subject.clone(),
            not_before,
            not_after,
            measured_on,
        });
    }
    if !header_seen {
        problems.push(format!("{PINS}: the header `{header}` is missing"));
    }
    pins
}

/// Binds the file to the rules: every `allow: signer_cert_sha256` has exactly one row, and every row
/// names a certificate its rule allows. A certificate entry with no row would expire unwatched; a row
/// with no entry would warn about a certificate nothing allows.
pub fn check_against_bundle(pins: &[Pin], bundle: &Bundle, problems: &mut Vec<String>) {
    let mut allowed: BTreeMap<(String, String), &str> = BTreeMap::new();
    for sourced in bundle.rules() {
        for allow in &sourced.rule.allow {
            if let Some(cert) = &allow.signer_cert_sha256 {
                allowed.insert(
                    (sourced.rule.id.clone(), cert.to_ascii_lowercase()),
                    sourced.path.as_str(),
                );
            }
        }
    }
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for pin in pins {
        let key = (pin.rule_id.clone(), pin.signer_cert_sha256.clone());
        if !allowed.contains_key(&key) {
            problems.push(format!(
                "{PINS}:{}: rule `{}` has no `allow: signer_cert_sha256: {}`; a pin for a certificate no rule allows watches nothing",
                pin.line, pin.rule_id, pin.signer_cert_sha256
            ));
        }
        if !seen.insert(key) {
            problems.push(format!(
                "{PINS}:{}: rule `{}` and certificate `{}` are pinned twice",
                pin.line, pin.rule_id, pin.signer_cert_sha256
            ));
        }
    }
    for ((rule_id, cert), path) in &allowed {
        if !seen.contains(&(rule_id.clone(), cert.clone())) {
            problems.push(format!(
                "rules/{path}: `allow: signer_cert_sha256: {cert}` has no row in `{PINS}`. A certificate entry goes stale when the publisher renews, so its subject, `not_before`, `not_after` and the date they were measured are recorded there, and a scheduled check warns before `not_after` (ADR 0036)"
            ));
        }
    }
}

/// The pins the scheduled check fails on, with how many days are left (negative once passed).
///
/// Only the pin with the latest `not_after` of each rule counts: once the renewed certificate is
/// measured and pinned beside the old one, the old one keeps being allowed for players who have not
/// updated, and its date has stopped being a warning about anything.
pub fn expiring(pins: &[Pin], today: Date) -> anyhow::Result<Vec<(&Pin, i32)>> {
    let mut newest: BTreeMap<&str, &Pin> = BTreeMap::new();
    for pin in pins {
        let slot = newest.entry(pin.rule_id.as_str()).or_insert(pin);
        if pin.not_after > slot.not_after {
            *slot = pin;
        }
    }
    let mut due = Vec::new();
    for pin in newest.into_values() {
        let last_day = pin.not_after.to_zoned(TimeZone::UTC).date();
        let days = today.until(last_day)?.get_days();
        if days <= WARN_DAYS {
            due.push((pin, days));
        }
    }
    Ok(due)
}

/// Arguments of `cargo xtask check-pin-expiry`.
#[derive(clap::Args)]
pub struct Args {
    /// Check as of this UTC date (`YYYY-MM-DD`) instead of today, to see what the schedule will say.
    #[arg(long)]
    today: Option<String>,
}

/// `cargo xtask check-pin-expiry`. Run by the monthly schedule, never on a pull request.
pub fn run_expiry(root: &Path, args: &Args) -> anyhow::Result<()> {
    let today = match &args.today {
        Some(date) => date
            .parse::<Date>()
            .with_context(|| format!("`--today {date}` is not a date such as 2026-09-14"))?,
        None => Timestamp::now().to_zoned(TimeZone::UTC).date(),
    };
    let mut problems = Vec::new();
    let pins = read(root, &mut problems)?;
    let bundle = Bundle::embedded().context("the embedded rules bundle is invalid")?;
    check_against_bundle(&pins, &bundle, &mut problems);
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("error: {problem}");
        }
        bail!("check-pin-expiry: {} problem(s) in {PINS}", problems.len());
    }
    let due = expiring(&pins, today)?;
    for pin in &pins {
        println!(
            "{}: rule {} allows certificate {} ({}), valid {} to {}, measured {}",
            PINS,
            pin.rule_id,
            pin.signer_cert_sha256,
            pin.subject,
            pin.not_before,
            pin.not_after,
            pin.measured_on
        );
    }
    if due.is_empty() {
        println!(
            "check-pin-expiry: as of {today}, no rule's newest pinned certificate reaches `not_after` within {WARN_DAYS} days"
        );
        return Ok(());
    }
    for (pin, days) in &due {
        eprintln!(
            "error: rule `{}` pins certificate `{}` ({}), whose `not_after` {} is {days} day(s) from {today}. When FiveM's publisher signs with a renewed certificate, the rule fires for every player who has updated. Measure the certificate of a FiveM.exe updated by FiveM itself on a machine of your own, add it beside this `allow` entry with a row in {PINS}, and keep this entry for players who have not updated (ADR 0036)",
            pin.rule_id, pin.signer_cert_sha256, pin.subject, pin.not_after
        );
    }
    bail!(
        "check-pin-expiry: {} pinned certificate(s) within {WARN_DAYS} days of `not_after`",
        due.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "65866007102ff66498c1ef739cf23dff71ae3d08da0d9d759b89d1a409c4208f";

    fn table(rows: &str) -> String {
        format!("# a comment\n{}\n{rows}", COLUMNS.join(","))
    }

    fn row(rule: &str, cert: &str, not_after: &str) -> String {
        format!(
            "{rule},{cert},\"CN=\"\"Example, Inc.\"\", C=US\",2026-07-21T00:00:00Z,{not_after},2026-09-13\n"
        )
    }

    fn parsed(text: &str) -> (Vec<Pin>, Vec<String>) {
        let mut problems = Vec::new();
        let pins = parse(text, &mut problems);
        (pins, problems)
    }

    #[test]
    fn a_well_formed_row_parses_with_its_quoted_subject() {
        let (pins, problems) = parsed(&table(&row("r", CERT, "2027-09-05T23:59:59Z")));
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].subject, r#"CN="Example, Inc.", C=US"#);
        assert_eq!(pins[0].measured_on, jiff::civil::date(2026, 9, 13));
    }

    #[test]
    fn malformed_values_are_problems() {
        let text = table(&format!(
            "{}{}{}",
            row("r", &CERT.to_uppercase(), "2027-09-05T23:59:59Z"),
            row("r", CERT, "2027-09-05"),
            row("r", CERT, "2026-01-01T00:00:00Z"),
        ));
        let (pins, problems) = parsed(&text);
        assert!(pins.is_empty(), "{pins:?}");
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems[0].contains("64 lowercase hex"), "{problems:?}");
        assert!(
            problems[1].contains("`not_after` must be an RFC 3339"),
            "{problems:?}"
        );
        assert!(problems[2].contains("is not before"), "{problems:?}");
    }

    fn pin(rule: &str, not_after: &str) -> Pin {
        let (mut pins, problems) = parsed(&table(&row(rule, CERT, not_after)));
        assert!(problems.is_empty(), "{problems:?}");
        pins.remove(0)
    }

    /// The boundary the scheduled check sits on: 91 days out is quiet, 90 is not, and a date that has
    /// passed is not either.
    #[test]
    fn a_pin_is_due_from_warn_days_before_not_after() {
        let pins = [pin("r", "2027-09-05T23:59:59Z")];
        let due = |today| expiring(&pins, today).unwrap().len();
        assert_eq!(due(jiff::civil::date(2026, 9, 14)), 0);
        assert_eq!(due(jiff::civil::date(2027, 6, 6)), 0, "91 days before");
        assert_eq!(due(jiff::civil::date(2027, 6, 7)), 1, "90 days before");
        assert_eq!(due(jiff::civil::date(2027, 10, 1)), 1, "after it passed");
    }

    /// Once a renewed certificate is pinned beside the old one, the old date stops warning.
    #[test]
    fn only_the_newest_pin_of_a_rule_counts() {
        let mut renewed = pin("r", "2028-10-01T00:00:00Z");
        renewed.signer_cert_sha256 = "c".repeat(64);
        let pins = [pin("r", "2027-09-05T23:59:59Z"), renewed];
        assert!(
            expiring(&pins, jiff::civil::date(2027, 9, 1))
                .unwrap()
                .is_empty()
        );
        let other_rule = [
            pin("r", "2028-10-01T00:00:00Z"),
            pin("s", "2027-09-05T23:59:59Z"),
        ];
        assert_eq!(
            expiring(&other_rule, jiff::civil::date(2027, 9, 1))
                .unwrap()
                .len(),
            1
        );
    }
}
