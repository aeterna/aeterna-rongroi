// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What the CLI writes to standard output and what it writes to standard error, run as a real
//! process. Standard output is the report and nothing else, so that `--json > report.json` holds JSON
//! and the questions a player has to answer still reach the player.

// The helpers below are test code; clippy.toml's `allow-expect-in-tests` reaches only `#[test]` functions.
#![allow(clippy::expect_used)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// Runs the CLI with `args`, feeding it `input` on standard input.
fn run(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aeterna-rongroi-cli"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the CLI starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input.as_bytes())
        .expect("input is written");
    child.wait_with_output().expect("the CLI exits")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("output is UTF-8")
}

#[test]
fn the_consent_question_goes_to_standard_error_and_the_json_to_standard_output() {
    let output = run(&["scan", "--mode", "ss", "--json"], "y\n");
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("SS mode") && stderr.contains("[y/N]"),
        "{stderr}"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("standard output is only the JSON report");
    assert_eq!(report["mode"], "ss");
}

#[test]
fn refusing_writes_nothing_to_standard_output() {
    let output = run(&["scan", "--mode", "ss", "--json"], "n\n");
    assert!(output.status.success());
    assert!(output.stdout.is_empty(), "{}", text(&output.stdout));
    assert!(text(&output.stderr).contains("Scan cancelled. Nothing was read."));
}

/// The pause the elevated copy is started with asks on standard error and ends at end of input, so a
/// copy with no keyboard behind it exits instead of hanging.
#[test]
fn pause_at_exit_asks_on_standard_error_and_ends_at_end_of_input() {
    let output = run(&["scan", "--json", "--pause-at-exit"], "");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("Press Enter to close this window."));
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .expect("the pause adds nothing to standard output");
}
