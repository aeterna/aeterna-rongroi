// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Tests for `cargo xtask lab-check`.

use std::collections::BTreeSet;

use serde_json::{Value, json};

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

/// A scan JSON with `evidence` rows for `states` and the given `game_windows` value (`null` for none).
fn scan_with_game_windows(states: &[(&str, &str)], game_windows: Value) -> String {
    let rows: Vec<Value> = states
        .iter()
        .map(|(id, state)| json!({"rule_id": id, "state": state}))
        .collect();
    json!({
        "header": {"os_build": "26300", "elevated": true},
        "evidence": rows,
        "game_windows": game_windows,
    })
    .to_string()
}

/// A `game_windows` value with the given candidates and `changes` clock change entries.
fn game_windows_value(candidates: Vec<Value>, changes: usize) -> Value {
    let change = json!({"from": "2026-10-27T20:00:00Z", "to": "2026-10-27T20:05:00Z"});
    json!({
        "candidates": candidates,
        "clock": {"changes": vec![change; changes]},
    })
}

/// One candidate as the scan writes it: `t1` as a plain fact, `i1` not known for `i1_reason`.
fn candidate_json(name: &str, t1: &str, i1_reason: &str) -> Value {
    json!({
        "name": name,
        "facts": {
            "t1": {"fact": t1},
            "i1": {"fact": "not_known", "reason": {"reason": i1_reason}},
        },
    })
}

/// A scan with no evidence, the given candidates and clock changes, parsed.
fn read_windows_scan(candidates: Vec<Value>, changes: usize) -> Scan {
    parse_scan(&scan_with_game_windows(
        &[],
        game_windows_value(candidates, changes),
    ))
    .expect("the scan parses")
}

/// The `game_windows` block of an `expect.yaml`, one entry per `(name, facts)`.
fn windows_yaml(entries: &[(&str, &[(&str, &str)])]) -> String {
    let mut text = String::from("game_windows:\n");
    for (name, facts) in entries {
        text.push_str(&format!("  - name: \"{name}\"\n    facts:\n"));
        for (key, value) in facts.iter() {
            text.push_str(&format!("      {key}: \"{value}\"\n"));
        }
    }
    text
}

/// An `expect.yaml` with an empty `found` and the given `game_windows` entries, parsed.
fn expect_windows(entries: &[(&str, &[(&str, &str)])]) -> Expect {
    parse_expect(&format!("found: []\n{}", windows_yaml(entries))).expect("the expect parses")
}

#[test]
fn an_expect_with_only_game_windows_is_accepted() {
    let expect = expect_windows(&[("helper.exe", &[("t1", "true")])]);
    assert!(validate_expect(&expect, &known_ids(&[])).is_ok());
}

#[test]
fn an_expect_with_nothing_expected_is_refused() {
    let expect = parse_expect("found: []\n").expect("an empty expect parses");
    let err = validate_expect(&expect, &known_ids(&[]))
        .expect_err("an expect with nothing expected is refused");
    let message = err.to_string();
    for word in ["found", "game_windows", "clock_changed"] {
        assert!(message.contains(word), "{message}");
    }
}

#[test]
fn an_unknown_fact_key_is_refused() {
    let expect = expect_windows(&[("helper.exe", &[("t5", "true")])]);
    let err = validate_expect(&expect, &known_ids(&[]))
        .expect_err("a fact key outside t1-t4, i1-i5, l1 is refused");
    let message = err.to_string();
    assert!(message.contains("t5"), "{message}");
}

#[test]
fn an_unknown_fact_value_is_refused() {
    for value in ["maybe", "not_known:", "not_known:No-Path"] {
        let expect = expect_windows(&[("helper.exe", &[("i1", value)])]);
        let err = validate_expect(&expect, &known_ids(&[]))
            .expect_err("a fact value outside true, false, not_known[:reason] is refused");
        let message = err.to_string();
        assert!(message.contains(value), "{value:?}: {message}");
    }
}

#[test]
fn a_candidate_named_twice_is_refused() {
    let expect = expect_windows(&[
        ("Helper.EXE", &[("t1", "true")]),
        ("helper.exe", &[("t1", "false")]),
    ]);
    let err = validate_expect(&expect, &known_ids(&[]))
        .expect_err("a candidate name repeated without regard to ASCII case is refused");
    let message = err.to_string().to_ascii_lowercase();
    assert!(message.contains("helper.exe"), "{message}");
}

#[test]
fn an_empty_candidate_name_is_refused() {
    let expect = expect_windows(&[("", &[("t1", "true")])]);
    assert!(validate_expect(&expect, &known_ids(&[])).is_err());
}

#[test]
fn full_and_clock_changed_parse() {
    let expect = parse_expect(&format!(
        "found:\n  - {FOUND}\nfull: true\nclock_changed: true\n"
    ))
    .expect("full and clock_changed parse");
    assert!(expect.full);
    assert_eq!(expect.clock_changed, Some(true));
    assert!(validate_expect(&expect, &known_ids(&[FOUND])).is_ok());
    assert!(!expect_both().full);
    assert_eq!(expect_both().clock_changed, None);
}

#[test]
fn an_unknown_field_inside_a_candidate_is_refused() {
    let text = "found: []\ngame_windows:\n  - name: \"helper.exe\"\n    facts:\n      t1: \"true\"\n    colour: \"red\"\n";
    assert!(parse_expect(text).is_err());
}

#[test]
fn a_candidate_fact_that_holds_passes() {
    let expect = expect_windows(&[("helper.exe", &[("t1", "true"), ("i1", "not_known:no_path")])]);
    let scan = read_windows_scan(vec![candidate_json("Helper.EXE", "true", "no_path")], 0);
    let report = check(&expect, &scan, None);
    assert_eq!(report.ok, 2, "{:?}", report.lines);
    assert_eq!(report.failed, 0, "{:?}", report.lines);
    assert!(report.lines.contains(&"ok    fact       helper.exe t1".to_owned()));
    assert!(report.lines.contains(&"ok    fact       helper.exe i1".to_owned()));
}

#[test]
fn a_bare_not_known_matches_any_reason() {
    let expect = expect_windows(&[("helper.exe", &[("i1", "not_known")])]);
    let scan = read_windows_scan(vec![candidate_json("Helper.EXE", "true", "no_path")], 0);
    let report = check(&expect, &scan, None);
    assert_eq!(
        report,
        Report {
            lines: vec!["ok    fact       helper.exe i1".to_owned()],
            ok: 1,
            failed: 0,
        }
    );
}

#[test]
fn a_fact_that_differs_fails_and_names_what_the_scan_read() {
    let scan = read_windows_scan(vec![candidate_json("Helper.EXE", "true", "no_path")], 0);

    let expect = expect_windows(&[("helper.exe", &[("t1", "false")])]);
    let report = check(&expect, &scan, None);
    assert_eq!(
        report,
        Report {
            lines: vec!["FAIL  fact       helper.exe t1 read true".to_owned()],
            ok: 0,
            failed: 1,
        }
    );

    let expect = expect_windows(&[("helper.exe", &[("i1", "not_known:recorded_files_not_run")])]);
    let report = check(&expect, &scan, None);
    assert_eq!(
        report,
        Report {
            lines: vec!["FAIL  fact       helper.exe i1 read not_known:no_path".to_owned()],
            ok: 0,
            failed: 1,
        }
    );
}

#[test]
fn a_missing_candidate_fails() {
    let expect = expect_windows(&[("other.exe", &[("t1", "true"), ("i1", "not_known")])]);
    let scan = read_windows_scan(vec![candidate_json("Helper.EXE", "true", "no_path")], 0);
    let report = check(&expect, &scan, None);
    assert_eq!(report.failed, 1, "{:?}", report.lines);
    assert_eq!(report.lines.len(), 1, "{:?}", report.lines);
    assert!(report.lines[0].starts_with("FAIL  candidate"), "{:?}", report.lines);
    assert!(
        report.lines[0].ends_with(" not a candidate"),
        "{:?}",
        report.lines
    );
}

#[test]
fn a_scan_with_no_view_fails() {
    let no_view = [
        scan(&[], true),
        scan_with_game_windows(&[], Value::Null),
    ];
    let expect = expect_windows(&[("helper.exe", &[("t1", "true"), ("i1", "not_known")])]);
    for text in no_view {
        let scan = parse_scan(&text).expect("the scan parses");
        let report = check(&expect, &scan, None);
        assert_eq!(report.failed, 1, "{:?}", report.lines);
        assert_eq!(report.lines.len(), 1, "{:?}", report.lines);
        assert!(report.lines[0].starts_with("FAIL  view"), "{:?}", report.lines);
        assert!(
            report.lines[0].ends_with(" no game-window view in the scan"),
            "{:?}",
            report.lines
        );
    }
}

#[test]
fn two_candidates_of_one_name_pass_when_either_holds_every_fact() {
    let expect = expect_windows(&[("helper.exe", &[("t1", "true"), ("i1", "not_known:no_path")])]);
    let scan = read_windows_scan(
        vec![
            candidate_json("Helper.EXE", "false", "no_path"),
            candidate_json("Helper.EXE", "true", "no_path"),
        ],
        0,
    );
    let report = check(&expect, &scan, None);
    assert_eq!(report.ok, 2, "{:?}", report.lines);
    assert_eq!(report.failed, 0, "{:?}", report.lines);
}

#[test]
fn two_candidates_of_one_name_do_not_mix_their_facts() {
    let expect = expect_windows(&[("helper.exe", &[("t1", "true"), ("i1", "not_known:no_path")])]);
    let scan = read_windows_scan(
        vec![
            candidate_json("Helper.EXE", "true", "recorded_files_not_run"),
            candidate_json("Helper.EXE", "false", "no_path"),
        ],
        0,
    );
    let report = check(&expect, &scan, None);
    assert_eq!(report.ok, 1, "{:?}", report.lines);
    assert_eq!(report.failed, 1, "{:?}", report.lines);
    assert!(
        report
            .lines
            .contains(&"FAIL  fact       helper.exe i1 read not_known:recorded_files_not_run".to_owned()),
        "{:?}",
        report.lines
    );
}

#[test]
fn a_candidate_fact_of_the_wrong_shape_is_an_error_naming_it() {
    let text = scan_with_game_windows(
        &[],
        game_windows_value(
            vec![json!({"name": "Helper.EXE", "facts": {"t1": {"nope": "x"}}})],
            0,
        ),
    );
    let err = parse_scan(&text).expect_err("a fact object of the wrong shape is refused");
    let message = format!("{err:#}");
    assert!(message.contains("Helper.EXE"), "{message}");
    assert!(message.contains("t1"), "{message}");
}

#[test]
fn clock_changed_true_needs_a_change() {
    let expect = parse_expect("found: []\nclock_changed: true\n").expect("the expect parses");
    let changed = read_windows_scan(vec![], 1);
    assert_eq!(
        check(&expect, &changed, None),
        Report {
            lines: vec!["ok    clock      changes".to_owned()],
            ok: 1,
            failed: 0,
        }
    );
    let unchanged = read_windows_scan(vec![], 0);
    assert_eq!(
        check(&expect, &unchanged, None),
        Report {
            lines: vec!["FAIL  clock      changes read 0".to_owned()],
            ok: 0,
            failed: 1,
        }
    );
}

#[test]
fn clock_changed_false_needs_none() {
    let expect = parse_expect("found: []\nclock_changed: false\n").expect("the expect parses");
    let unchanged = read_windows_scan(vec![], 0);
    assert_eq!(
        check(&expect, &unchanged, None),
        Report {
            lines: vec!["ok    clock      changes".to_owned()],
            ok: 1,
            failed: 0,
        }
    );
    let changed = read_windows_scan(vec![], 1);
    assert_eq!(
        check(&expect, &changed, None),
        Report {
            lines: vec!["FAIL  clock      changes read 1".to_owned()],
            ok: 0,
            failed: 1,
        }
    );
}

#[test]
fn game_window_expectations_add_no_ledger_row() {
    let expect = parse_expect(&format!(
        "found:\n  - {FOUND}\n{}",
        windows_yaml(&[("helper.exe", &[("t1", "true")])])
    ))
    .expect("the expect parses");
    let text = scan_with_game_windows(
        &[(FOUND, "found")],
        game_windows_value(vec![candidate_json("Helper.EXE", "true", "no_path")], 0),
    );
    let scan = parse_scan(&text).expect("the scan parses");
    let report = check(&expect, &scan, None);
    assert_eq!(report.failed, 0, "{:?}", report.lines);
    let rows = ledger_rows(&expect, &scan, "lab/scenarios/x (run r)", "2026-10-18");
    assert_eq!(
        rows,
        vec![format!(
            "{FOUND},lab-vm-arm64,26300,client,arm64,elevated,found,lab/scenarios/x (run r),2026-10-18"
        )]
    );
}

#[test]
fn a_scan_without_game_windows_still_parses() {
    let parsed = parse_scan(&scan(&[(FOUND, "found")], true)).expect("the scan parses");
    assert!(parsed.game_windows.is_none());
    assert_eq!(parsed.clock_changes, 0);
    assert_eq!(parsed.state(FOUND), "found");

    let null = parse_scan(&scan_with_game_windows(&[], Value::Null)).expect("the scan parses");
    assert!(null.game_windows.is_none());
}
