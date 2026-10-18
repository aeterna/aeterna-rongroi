// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Unit tests for the ledger reader of ADR 0074 §1: `rules/measured.csv`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

/// A directory under the OS temp dir, unique per test, deleted on drop (even on panic) so a
/// failed assertion never leaves a ledger behind.
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
            "aeterna-rongroi-xtask-measured-{}-{label}-{n}-{nanos}",
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

const RULE_ID: &str = "00000000-0000-4000-8000-000000000001";

/// Column indexes of the nine fields, in header order.
const SUBJECT: usize = 0;
const MACHINE: usize = 1;
const OS_BUILD: usize = 2;
const EDITION: usize = 3;
const ARCH: usize = 4;
const TOKEN: usize = 5;
const SEEN: usize = 6;
const EVIDENCE: usize = 7;
const DATE: usize = 8;

/// A valid collector row: `pca` measured on an owner PC.
const COLLECTOR_ROW: &str = "pca,owner-pc,26100.4061,client,x64,elevated,observations,ci run 123,2026-10-18";
/// A valid rule row (`RULE_ID`) measured on a lab VM.
const RULE_ROW: &str = "00000000-0000-4000-8000-000000000001,lab-vm-arm64,26100,server,arm64,limited,found,docs/evidence/x.md,2026-10-18";

fn rule_ids() -> BTreeSet<String> {
    BTreeSet::from([RULE_ID.to_owned()])
}

fn collectors() -> BTreeSet<String> {
    BTreeSet::from(["pca".to_owned()])
}

fn day(text: &str) -> Date {
    text.parse().expect("a valid day")
}

/// A CSV row with one of its nine fields replaced. `value` is written as given, so a comma in it
/// must be quoted by the caller.
fn set_field(base: &str, field: usize, value: &str) -> String {
    let mut fields: Vec<&str> = base.split(',').collect();
    fields[field] = value;
    fields.join(",")
}

/// The header line followed by the given rows, each on its own line.
fn with_header(records: &[String]) -> String {
    let mut text = format!("{HEADER}\n");
    for record in records {
        text.push_str(record);
        text.push('\n');
    }
    text
}

/// Writes `text` as the ledger under `tmp` and reads it back.
fn read_text(tmp: &TempRoot, text: &str) -> (Vec<Measured>, Vec<String>) {
    write(&tmp.path().join(MEASURED), text);
    read(tmp.path(), &rule_ids(), &collectors()).expect("read the ledger")
}

/// The row `COLLECTOR_ROW` parses to when it sits on `line`.
fn collector(line: usize) -> Measured {
    Measured {
        line,
        subject: "pca".to_owned(),
        machine: "owner-pc".to_owned(),
        os_build: "26100.4061".to_owned(),
        edition: Edition::Client,
        arch: Arch::X64,
        token: Token::Elevated,
        seen: Seen::Observations,
        evidence: "ci run 123".to_owned(),
        date: day("2026-10-18"),
    }
}

/// The row `RULE_ROW` parses to when it sits on `line`.
fn rule(line: usize) -> Measured {
    Measured {
        line,
        subject: RULE_ID.to_owned(),
        machine: "lab-vm-arm64".to_owned(),
        os_build: "26100".to_owned(),
        edition: Edition::Server,
        arch: Arch::Arm64,
        token: Token::Limited,
        seen: Seen::Found,
        evidence: "docs/evidence/x.md".to_owned(),
        date: day("2026-10-18"),
    }
}

/// Asserts that one row on line 2 is rejected with exactly `message` and no row is returned.
fn rejected(label: &str, record: String, message: &str) {
    let tmp = TempRoot::new(label);
    let (parsed, problems) = read_text(&tmp, &with_header(&[record]));
    assert!(parsed.is_empty(), "a failed row is not returned, got {parsed:?}");
    assert_eq!(problems, [format!("{MEASURED}:2: {message}")]);
}

fn machine_message(value: &str) -> String {
    format!(
        "`machine` `{value}` must be `owner-pc`, `lab-vm-arm64`, or `gha-<label>`, where the label is lowercase letters, digits and `-`, and does not start or end with `-`"
    )
}

fn os_build_message(value: &str) -> String {
    format!(
        "`os_build` `{value}` must be digits, optionally a `.` and digits, with no leading zero (for example `26100` or `26100.4061`)"
    )
}

fn date_message(value: &str) -> String {
    format!("`date` `{value}` must be a day written `YYYY-MM-DD`")
}

fn collector_seen_message(value: &str) -> String {
    format!(
        "`seen` `{value}` is not allowed on a collector: a collector takes `observations`, `none`, or `unmeasured:<reason>`"
    )
}

fn rule_seen_message(value: &str) -> String {
    format!(
        "`seen` `{value}` is not allowed on a rule: a rule takes `found`, `not_found`, or `unmeasured:<reason>`"
    )
}

#[test]
fn an_absent_ledger_and_a_header_alone_are_no_rows_and_no_problems() {
    let tmp = TempRoot::new("empty");
    let (rows, problems) = read(tmp.path(), &rule_ids(), &collectors()).expect("read the ledger");
    assert!(rows.is_empty() && problems.is_empty(), "absent: {rows:?} {problems:?}");
    let (rows, problems) = read_text(&tmp, &format!("{HEADER}\n"));
    assert!(rows.is_empty() && problems.is_empty(), "header only: {rows:?} {problems:?}");
}

#[test]
fn comment_and_blank_lines_before_the_header_are_skipped_and_counted() {
    let tmp = TempRoot::new("leading-lines");
    let (rows, problems) = read_text(&tmp, &format!("\n# a note\n{HEADER}\n{COLLECTOR_ROW}\n"));
    assert_eq!(rows, [collector(4)], "the row is on physical line 4");
    assert!(problems.is_empty(), "unexpected problems: {problems:?}");
}

#[test]
fn a_collector_row_and_a_rule_row_parse_to_their_fields() {
    let tmp = TempRoot::new("valid-rows");
    let text = with_header(&[COLLECTOR_ROW.to_owned(), RULE_ROW.to_owned()]);
    let (rows, problems) = read_text(&tmp, &text);
    assert_eq!(rows, [collector(2), rule(3)]);
    assert!(problems.is_empty(), "unexpected problems: {problems:?}");
}

#[test]
fn each_seen_keyword_is_accepted_for_the_kind_that_takes_it() {
    let tmp = TempRoot::new("seen-keywords");
    let text = with_header(&[
        set_field(COLLECTOR_ROW, SEEN, "none"),
        set_field(RULE_ROW, SEEN, "not_found"),
        set_field(RULE_ROW, SEEN, "unmeasured:no probe on this host"),
        set_field(COLLECTOR_ROW, SEEN, "unmeasured:VM has no TPM"),
    ]);
    let (rows, problems) = read_text(&tmp, &text);
    let seen: Vec<Seen> = rows.into_iter().map(|parsed| parsed.seen).collect();
    assert_eq!(
        seen,
        [
            Seen::None,
            Seen::NotFound,
            Seen::Unmeasured("no probe on this host".to_owned()),
            Seen::Unmeasured("VM has no TPM".to_owned()),
        ]
    );
    assert!(problems.is_empty(), "unexpected problems: {problems:?}");
}

#[test]
fn an_unknown_subject_is_reported_and_its_seen_is_checked_for_shape_only() {
    let tmp = TempRoot::new("unknown-subject");
    // With no kind, `found` is well formed, so only the subject fails.
    let row = set_field(&set_field(COLLECTOR_ROW, SUBJECT, "nope"), SEEN, "found");
    let (rows, problems) = read_text(&tmp, &with_header(&[row]));
    assert!(rows.is_empty(), "a row with an unknown subject is not returned");
    let message = "`subject` `nope` is neither a rule in the bundle nor a collector";
    assert_eq!(problems, [format!("{MEASURED}:2: {message}")]);
}

#[test]
fn machine_values_outside_the_three_forms_are_reported() {
    for value in ["laptop", "Owner-PC", "gha-", "gha--x", "gha-x-", "gha-Win"] {
        let row = set_field(COLLECTOR_ROW, MACHINE, value);
        rejected("bad-machine", row, &machine_message(value));
    }
}

#[test]
fn os_build_values_outside_digits_dot_digits_are_reported() {
    for value in ["", "026100", "26100.", "26100.4061.1", "2610a", "26100.04061"] {
        let row = set_field(COLLECTOR_ROW, OS_BUILD, value);
        rejected("bad-os-build", row, &os_build_message(value));
    }
}

#[test]
fn an_edition_other_than_client_or_server_is_reported() {
    let row = set_field(COLLECTOR_ROW, EDITION, "Client");
    rejected("bad-edition", row, "`edition` `Client` must be `client` or `server`");
}

#[test]
fn an_arch_other_than_x64_or_arm64_is_reported() {
    let row = set_field(COLLECTOR_ROW, ARCH, "x86");
    rejected("bad-arch", row, "`arch` `x86` must be `x64` or `arm64`");
}

#[test]
fn a_token_other_than_elevated_or_limited_is_reported() {
    let row = set_field(COLLECTOR_ROW, TOKEN, "admin");
    rejected("bad-token", row, "`token` `admin` must be `elevated` or `limited`");
}

#[test]
fn a_collector_with_a_rule_keyword_in_seen_is_reported() {
    for value in ["found", "not_found"] {
        let row = set_field(COLLECTOR_ROW, SEEN, value);
        rejected("collector-rule-seen", row, &collector_seen_message(value));
    }
}

#[test]
fn a_rule_with_a_collector_keyword_in_seen_is_reported() {
    for value in ["observations", "none"] {
        let row = set_field(RULE_ROW, SEEN, value);
        rejected("rule-collector-seen", row, &rule_seen_message(value));
    }
}

#[test]
fn an_unmeasured_seen_with_no_reason_is_reported() {
    for value in ["unmeasured:", "unmeasured:   "] {
        let row = set_field(RULE_ROW, SEEN, value);
        let message = "`seen` `unmeasured:` needs a reason after the colon";
        rejected("unmeasured-no-reason", row, message);
    }
}

#[test]
fn an_empty_evidence_is_reported() {
    for value in ["", "   "] {
        let row = set_field(COLLECTOR_ROW, EVIDENCE, value);
        let message = "`evidence` must not be empty: give a CI run id, a path under `docs/`, or the name of a probe result";
        rejected("empty-evidence", row, message);
    }
}

#[test]
fn a_date_not_written_as_a_real_day_is_reported() {
    for value in ["2026-02-30", "2026/10/18", "2026-1-05", "20261018", "2026-13-01", "18-10-2026"] {
        let row = set_field(COLLECTOR_ROW, DATE, value);
        rejected("bad-date", row, &date_message(value));
    }
}

#[test]
fn a_row_with_the_wrong_field_count_is_reported() {
    let short = COLLECTOR_ROW.rsplit_once(',').expect("nine fields").0.to_owned();
    let long = format!("{COLLECTOR_ROW},extra");
    for record in [short, long] {
        let found = record.split(',').count();
        rejected(
            "field-count",
            record,
            &format!("expected the 9 fields of `{HEADER}`, found {found}"),
        );
    }
}

#[test]
fn a_wrong_header_is_reported_and_the_rows_after_it_are_still_read() {
    let tmp = TempRoot::new("wrong-header");
    let short_header = "subject,machine,os_build,edition,arch,token,seen,evidence";
    let (rows, problems) = read_text(&tmp, &format!("{short_header}\n{COLLECTOR_ROW}\n"));
    assert_eq!(rows, [collector(2)]);
    assert_eq!(problems, [format!("{MEASURED}:1: the header must be `{HEADER}`")]);
}

#[test]
fn a_ledger_with_no_header_is_reported() {
    let tmp = TempRoot::new("no-header");
    let (rows, problems) = read_text(&tmp, "# no header here\n\n");
    assert!(rows.is_empty(), "no header means no rows, got {rows:?}");
    assert_eq!(problems, [format!("{MEASURED}: the header `{HEADER}` is missing")]);
}

#[test]
fn quoted_evidence_keeps_its_comma() {
    let tmp = TempRoot::new("quoted-evidence");
    let row = set_field(COLLECTOR_ROW, EVIDENCE, "\"ci run 1, job 2\"");
    let (rows, problems) = read_text(&tmp, &with_header(&[row]));
    assert_eq!(rows.len(), 1, "the quoted row is one row, got {rows:?}");
    assert_eq!(rows[0].evidence, "ci run 1, job 2");
    assert!(problems.is_empty(), "unexpected problems: {problems:?}");
}

#[test]
fn a_repeated_row_is_reported_and_names_the_line_it_repeats() {
    let tmp = TempRoot::new("duplicate");
    // The third row differs only in its date, so it is not a repeat.
    let differing = set_field(COLLECTOR_ROW, DATE, "2026-10-19");
    let text = with_header(&[COLLECTOR_ROW.to_owned(), COLLECTOR_ROW.to_owned(), differing]);
    let (rows, problems) = read_text(&tmp, &text);
    let lines: Vec<usize> = rows.iter().map(|parsed| parsed.line).collect();
    assert_eq!(lines, [2, 4], "the first row and the differing row are kept");
    assert_eq!(problems, [format!("{MEASURED}:3: repeats the row on line 2")]);
}

#[test]
fn a_bad_field_is_reported_on_its_own_physical_line_and_good_rows_still_parse() {
    let tmp = TempRoot::new("line-numbers");
    let bad = set_field(COLLECTOR_ROW, ARCH, "x86");
    let text = format!("# a note\n\n{HEADER}\n{COLLECTOR_ROW}\n{bad}\n");
    let (rows, problems) = read_text(&tmp, &text);
    assert_eq!(rows, [collector(4)]);
    assert_eq!(problems, [format!("{MEASURED}:5: `arch` `x86` must be `x64` or `arm64`")]);
}

#[test]
fn every_failed_field_of_a_row_is_reported_in_column_order() {
    let tmp = TempRoot::new("every-field");
    let bad = set_field(&set_field(COLLECTOR_ROW, MACHINE, "laptop"), DATE, "2026-02-30");
    let (rows, problems) = read_text(&tmp, &with_header(&[bad]));
    assert!(rows.is_empty(), "a row with failed fields is not returned");
    let expected = [
        format!("{MEASURED}:2: {}", machine_message("laptop")),
        format!("{MEASURED}:2: {}", date_message("2026-02-30")),
    ];
    assert_eq!(problems, expected);
}
