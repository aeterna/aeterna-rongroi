// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The sidecar's exit codes, run as a real process. Arguments are checked before anything else, so a
//! refused pipe name exits 1 without writing standard output or reaching the pipe.

// The helper below is test code; clippy.toml's `allow-expect-in-tests` reaches only `#[test]` functions.
#![allow(clippy::expect_used)]

use std::process::{Command, Output};

/// Runs the sidecar with `args`.
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rongroi-scan"))
        .args(args)
        .output()
        .expect("the sidecar starts")
}

#[test]
fn a_bad_pipe_name_exits_1_before_anything_else() {
    let names = [
        r"\\.\pipe\rongroi-0123456789abcdef0123456789abcde",
        r"\\.\pipe\rongroi-0123456789ABCDEF0123456789ABCDEF",
        r"\\server\pipe\rongroi-0123456789abcdef0123456789abcdef",
        "//./pipe/rongroi-0123456789abcdef0123456789abcdef",
        r"\\.\pipe\rongroi-0123456789abcdef0123456789abcdef\x",
        "\\.\\pipe\\rongroi-0123456789abcdef0123456789abcdef\n",
    ];
    for name in names {
        for extra in [&[][..], &["--elevate"][..]] {
            let mut args = vec!["--pipe", name];
            args.extend_from_slice(extra);
            let output = run(&args);
            assert_eq!(output.status.code(), Some(1), "{name:?} {extra:?}");
            assert!(output.stdout.is_empty(), "{name:?} {extra:?}");
            let stderr = String::from_utf8(output.stderr).expect("standard error is UTF-8");
            assert!(
                stderr.contains("arguments were refused"),
                "{name:?} {extra:?}: {stderr}"
            );
        }
    }
}

#[test]
fn a_missing_or_unknown_argument_exits_1() {
    let pipe = r"\\.\pipe\rongroi-0123456789abcdef0123456789abcdef";
    for args in [
        &[][..],
        &["--pipe"][..],
        &["--elevate"][..],
        &["--pipe", pipe, "--pause-at-exit"][..],
        &["--pipe", pipe, "--unknown"][..],
        &["--pipe", pipe, "extra"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let stderr = String::from_utf8(output.stderr).expect("standard error is UTF-8");
        assert!(
            stderr.contains("arguments were refused"),
            "{args:?}: {stderr}"
        );
    }
}

/// This system has no named pipes, so a well-formed name reaches the platform check and exits 1 with
/// the Windows-only line rather than trying to open anything.
#[cfg(not(windows))]
#[test]
fn a_well_formed_pipe_on_this_system_exits_1_with_a_windows_only_line() {
    let pipe = r"\\.\pipe\rongroi-0123456789abcdef0123456789abcdef";
    let output = run(&["--pipe", pipe]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("standard error is UTF-8");
    assert!(stderr.contains("Windows"), "{stderr}");
}
