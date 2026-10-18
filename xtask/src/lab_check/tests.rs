// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Tests for `cargo xtask lab-check`.

use std::collections::BTreeSet;

use super::*;

const FOUND: &str = "fc74cf1c-a134-45f1-83bd-db42a4dab748";
const NEIGH: &str = "ae2f3bb9-a3ee-4175-bf89-982b9fbbbe08";

/// A scan JSON with the given `(rule_id, state)` evidence rows, header `os_build` `26300`.
fn scan(states: &[(&str, &str)], elevated: bool) -> String {
    let rows: Vec<String> = states
        .iter()
        .map(|(id, state)| format!(r#"{{"rule_id":"{id}","state":"{state}"}}"#))
        .collect();
    format!(
        r#"{{"header":{{"os_build":"26300","elevated":{elevated}}},"evidence":[{}]}}"#,
        rows.join(",")
    )
}

/// The scan JSON from [`scan`], parsed.
fn read_scan(states: &[(&str, &str)], elevated: bool) -> Scan {
    parse_scan(&scan(states, elevated)).expect("the scan parses")
}

/// The `expect.yaml` of a scenario that needs FOUND and neighbours NEIGH.
fn expect_both() -> Expect {
    parse_expect(&format!("found:\n  - {FOUND}\nnot_found:\n  - {NEIGH}\n"))
        .expect("the expect parses")
}

fn known_ids(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

#[test]
fn every_check_passing_gives_two_ok_lines_and_no_failure() {
    let expect = expect_both();
    let scan = read_scan(&[(FOUND, "found"), (NEIGH, "not_found")], true);
    let report = check(&expect, &scan, None);
    assert_eq!(
        report,
        Report {
            lines: vec![
                format!("ok    found      {FOUND}"),
                format!("ok    not_found  {NEIGH}"),
            ],
            ok: 2,
            failed: 0,
        }
    );
}

#[test]
fn a_found_rule_that_reads_not_found_fails_and_names_the_state() {
    let expect = expect_both();
    let scan = read_scan(&[(FOUND, "not_found"), (NEIGH, "not_found")], true);
    let report = check(&expect, &scan, None);
    assert_eq!(
        report,
        Report {
            lines: vec![
                format!("FAIL  found      {FOUND} read not_found"),
                format!("ok    not_found  {NEIGH}"),
            ],
            ok: 1,
            failed: 1,
        }
    );
}

#[test]
fn a_found_rule_missing_from_evidence_reads_absent() {
    let expect = expect_both();
    let scan = read_scan(&[(NEIGH, "not_found")], true);
    let report = check(&expect, &scan, None);
    assert_eq!(
        report,
        Report {
            lines: vec![
                format!("FAIL  found      {FOUND} read absent"),
                format!("ok    not_found  {NEIGH}"),
            ],
            ok: 1,
            failed: 1,
        }
    );
}

#[test]
fn a_neighbour_that_reads_found_fails() {
    let expect = expect_both();
    let scan = read_scan(&[(FOUND, "found"), (NEIGH, "found")], true);
    let report = check(&expect, &scan, None);
    assert_eq!(
        report,
        Report {
            lines: vec![
                format!("ok    found      {FOUND}"),
                format!("FAIL  not_found  {NEIGH} read found"),
            ],
            ok: 1,
            failed: 1,
        }
    );
}

#[test]
fn a_control_that_reads_found_fails_with_no_scenario() {
    let expect = expect_both();
    let scan = read_scan(&[(FOUND, "found"), (NEIGH, "not_found")], true);
    let control = read_scan(&[(FOUND, "found"), (NEIGH, "not_found")], false);
    let report = check(&expect, &scan, Some(&control));
    assert_eq!(
        report,
        Report {
            lines: vec![
                format!("ok    found      {FOUND}"),
                format!("FAIL  control    {FOUND} read found with no scenario"),
                format!("ok    not_found  {NEIGH}"),
            ],
            ok: 2,
            failed: 1,
        }
    );
}

#[test]
fn a_control_that_does_not_read_found_passes() {
    let expect = expect_both();
    let scan = read_scan(&[(FOUND, "found"), (NEIGH, "not_found")], true);
    let control = read_scan(&[(FOUND, "not_found"), (NEIGH, "not_found")], false);
    let report = check(&expect, &scan, Some(&control));
    assert_eq!(
        report,
        Report {
            lines: vec![
                format!("ok    found      {FOUND}"),
                format!("ok    control    {FOUND}"),
                format!("ok    not_found  {NEIGH}"),
            ],
            ok: 3,
            failed: 0,
        }
    );
}

#[test]
fn without_a_control_there_is_no_control_line() {
    let expect = expect_both();
    let scan = read_scan(&[(FOUND, "found"), (NEIGH, "not_found")], true);
    let report = check(&expect, &scan, None);
    assert!(
        !report
            .lines
            .iter()
            .any(|line| line.starts_with("ok    control") || line.starts_with("FAIL  control")),
        "{:?}",
        report.lines
    );
}

#[test]
fn a_bom_prefixed_scan_parses_to_the_same_states() {
    let text = format!(
        "\u{feff}{}",
        scan(&[(FOUND, "found"), (NEIGH, "not_found")], true)
    );
    let parsed = parse_scan(&text).expect("a BOM-prefixed scan parses");
    assert_eq!(parsed.state(FOUND), "found");
    assert_eq!(parsed.state(NEIGH), "not_found");
    assert!(parsed.elevated);
    assert_eq!(parsed.os_build, "26300");
}

#[test]
fn extra_keys_in_a_real_scan_are_ignored() {
    let text = scan(&[(FOUND, "found")], false).replacen(
        "\"os_build\"",
        "\"platform\":\"windows\",\"os_build\"",
        1,
    );
    assert!(text.contains("\"platform\":\"windows\""), "{text}");
    let parsed = parse_scan(&text).expect("a scan with an extra header key parses");
    assert_eq!(parsed.state(FOUND), "found");
    assert!(!parsed.elevated);
}

#[test]
fn a_rule_listed_twice_in_a_scan_is_an_error() {
    let err = parse_scan(&scan(&[(FOUND, "found"), (FOUND, "not_found")], true))
        .expect_err("a rule listed twice is refused");
    let message = err.to_string();
    assert!(message.contains("twice"), "{message}");
    assert!(message.contains(FOUND), "{message}");
}

#[test]
fn a_scan_state_is_absent_for_a_rule_missing_from_evidence() {
    let scan = read_scan(&[(FOUND, "unmeasured")], true);
    assert_eq!(scan.state(FOUND), "unmeasured");
    assert_eq!(scan.state(NEIGH), "absent");
}

#[test]
fn expect_with_an_unknown_field_is_refused() {
    let text = format!("found:\n  - {FOUND}\nnot_fund:\n  - {NEIGH}\n");
    assert!(parse_expect(&text).is_err());
}

#[test]
fn expect_with_an_empty_found_is_refused() {
    let expect = parse_expect("found: []\n").expect("an empty found list parses");
    let err = validate_expect(&expect, &known_ids(&[FOUND, NEIGH]))
        .expect_err("an empty found list is refused");
    let message = err.to_string();
    assert!(message.contains("no `found` rule"), "{message}");
}

#[test]
fn expect_listing_an_id_twice_is_refused() {
    let expect = parse_expect(&format!("found:\n  - {FOUND}\nnot_found:\n  - {FOUND}\n"))
        .expect("the expect parses");
    let err =
        validate_expect(&expect, &known_ids(&[FOUND])).expect_err("a duplicate id is refused");
    let message = err.to_string();
    assert!(
        message.contains(&format!("{FOUND} is listed more than once")),
        "{message}"
    );
}

#[test]
fn expect_naming_an_id_not_in_known_is_refused() {
    let expect = expect_both();
    let err = validate_expect(&expect, &known_ids(&[FOUND]))
        .expect_err("an id outside the bundle is refused");
    let message = err.to_string();
    assert!(
        message.contains(&format!("{NEIGH} is not a rule id in rules/")),
        "{message}"
    );
    assert!(!message.contains(&format!("{FOUND} is not")), "{message}");
}

#[test]
fn a_valid_expect_passes_validation() {
    let expect = expect_both();
    assert!(validate_expect(&expect, &known_ids(&[FOUND, NEIGH])).is_ok());
}

#[test]
fn expect_restart_true_parses() {
    let expect = parse_expect(&format!("found:\n  - {FOUND}\nrestart: true\n"))
        .expect("restart: true parses");
    assert!(expect.restart);
    assert!(validate_expect(&expect, &known_ids(&[FOUND])).is_ok());
}

#[test]
fn ledger_rows_for_an_elevated_scan_name_each_expected_rule() {
    let expect = expect_both();
    let scan = read_scan(&[(FOUND, "found"), (NEIGH, "not_found")], true);
    let rows = ledger_rows(&expect, &scan, "lab/scenarios/x (run r)", "2026-10-18");
    assert_eq!(
        rows,
        vec![
            format!(
                "{FOUND},lab-vm-arm64,26300,client,arm64,elevated,found,lab/scenarios/x (run r),2026-10-18"
            ),
            format!(
                "{NEIGH},lab-vm-arm64,26300,client,arm64,elevated,not_found,lab/scenarios/x (run r),2026-10-18"
            ),
        ]
    );
}

#[test]
fn ledger_rows_for_a_limited_scan_say_limited() {
    let expect = expect_both();
    let scan = read_scan(&[(FOUND, "found"), (NEIGH, "not_found")], false);
    let rows = ledger_rows(&expect, &scan, "lab/scenarios/x (run r)", "2026-10-18");
    assert_eq!(
        rows[0],
        format!(
            "{FOUND},lab-vm-arm64,26300,client,arm64,limited,found,lab/scenarios/x (run r),2026-10-18"
        )
    );
    assert!(
        rows.iter().all(|row| !row.contains(",elevated,")),
        "{rows:?}"
    );
}

#[test]
fn ledger_evidence_with_a_comma_is_double_quoted() {
    let expect = expect_both();
    let scan = read_scan(&[(FOUND, "found"), (NEIGH, "not_found")], true);
    let rows = ledger_rows(&expect, &scan, "run 1, lab", "2026-10-18");
    assert_eq!(
        rows[0],
        format!("{FOUND},lab-vm-arm64,26300,client,arm64,elevated,found,\"run 1, lab\",2026-10-18")
    );
}

#[test]
fn ledger_evidence_with_a_double_quote_doubles_it_inside_the_quotes() {
    let expect = expect_both();
    let scan = read_scan(&[(FOUND, "found"), (NEIGH, "not_found")], true);
    let rows = ledger_rows(&expect, &scan, "probe \"x\"", "2026-10-18");
    assert_eq!(
        rows[0],
        format!(
            "{FOUND},lab-vm-arm64,26300,client,arm64,elevated,found,\"probe \"\"x\"\"\",2026-10-18"
        )
    );
}

#[test]
fn is_date_accepts_real_calendar_dates_and_refuses_the_rest() {
    let cases = [
        ("2026-10-18", true),
        ("2026-02-29", false),
        ("2024-02-29", true),
        ("2026-13-01", false),
        ("2026-1-01", false),
        ("20261018xx", false),
    ];
    for (text, want) in cases {
        assert_eq!(is_date(text), want, "is_date({text:?})");
    }
}
