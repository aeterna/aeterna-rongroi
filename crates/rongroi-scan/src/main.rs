// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Sidecar entry point: validate the pipe name, relaunch elevated when asked, then run one session.

#[cfg(windows)]
mod pipe_client;

use std::process::ExitCode;

use rongroi_host_windows::elevate::ElevateError;
use rongroi_scan::exit::ExitKind;
use rongroi_scan::pipe_name;

#[cfg(windows)]
use rongroi_collectors::scan::{self, ScanContext};
#[cfg(windows)]
use rongroi_core::bundle::Bundle;
#[cfg(windows)]
use rongroi_host::Host;
#[cfg(windows)]
use rongroi_scan::session;

/// The exit code for a failure that is not the player declining elevation.
const EXIT_FAILED: u8 = ExitKind::Failed.code();

/// The arguments the sidecar accepts, after validation.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
struct Args {
    /// The full name of the pipe Connect created.
    pipe: String,
    /// Whether Connect asked for an elevated scan.
    elevate: bool,
}

/// Why the sidecar's arguments were refused.
#[derive(Debug, PartialEq, Eq)]
enum ParseError {
    /// `--pipe` was missing, repeated, or had no value.
    Pipe,
    /// The name after `--pipe` is not one Connect creates.
    PipeName,
    /// An argument the sidecar does not accept.
    Unknown,
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(_) => {
            eprintln!("rongroi-scan: the arguments were refused");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    platform_run(&args)
}

/// Parses the sidecar's arguments by hand; clap is not a dependency of this binary.
///
/// A bad `--pipe` name is refused here, before any pipe is opened or any elevation is requested.
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, ParseError> {
    let mut pipe = None;
    let mut elevate = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pipe" => {
                if pipe.is_some() {
                    return Err(ParseError::Pipe);
                }
                let name = args.next().ok_or(ParseError::Pipe)?;
                pipe_name::validate(&name).map_err(|_| ParseError::PipeName)?;
                pipe = Some(name);
            }
            "--elevate" => elevate = true,
            _ => return Err(ParseError::Unknown),
        }
    }
    let pipe = pipe.ok_or(ParseError::Pipe)?;
    Ok(Args { pipe, elevate })
}

/// The arguments the elevated copy is started with, given this process's own.
///
/// `--elevate` is dropped, so the new process cannot ask to elevate again: a token that is elevated
/// but restricted reports `is_elevated() == false` and would otherwise relaunch in a loop (ADR 0012).
/// `--pause-at-exit` is never added: the sidecar has no window of its own for a person to read (ADR
/// 0012's amendment is CLI-only), and one that arrived for any reason is dropped too.
#[cfg_attr(not(windows), allow(dead_code))]
fn elevated_args(args: impl IntoIterator<Item = String>) -> Vec<String> {
    args.into_iter()
        .filter(|arg| arg != "--elevate" && arg != "--pause-at-exit")
        .collect()
}

/// The line to print and the exit code to use after asking Windows for an elevated copy.
///
/// A failure keeps only a fixed sentence: the error can name the program's own path, and no argument
/// value may cross the pipe or appear in the parent's output.
#[cfg_attr(not(windows), allow(dead_code))]
fn elevate_report(result: Result<(), ElevateError>) -> (&'static str, u8) {
    const REQUESTED: &str = r#"{"elevate":"requested"}"#;
    const DECLINED: &str = r#"{"elevate":"declined"}"#;
    const FAILED: &str = r#"{"elevate":"failed","message":"the elevated copy was not started"}"#;
    const EXIT_DECLINED: u8 = 3;

    match result {
        Ok(()) => (REQUESTED, 0),
        Err(ElevateError::Declined) => (DECLINED, EXIT_DECLINED),
        Err(_) => (FAILED, EXIT_FAILED),
    }
}

#[cfg(windows)]
fn live_host() -> Box<dyn Host> {
    Box::new(rongroi_host_windows::LiveHost)
}

#[cfg(windows)]
fn platform_run(args: &Args) -> ExitCode {
    use rongroi_host_windows::elevate::{ShowWindow, relaunch_elevated_with};

    let host = live_host();
    if args.elevate && host.is_elevated() != Some(true) {
        let forwarded = elevated_args(std::env::args().skip(1));
        let (line, code) = elevate_report(relaunch_elevated_with(&forwarded, ShowWindow::Hidden));
        println!("{line}");
        return ExitCode::from(code);
    }

    let Ok(mut transport) = pipe_client::open(&args.pipe) else {
        return ExitKind::Failed.into();
    };
    let scan_host = move |bundle: &Bundle, context: ScanContext, ids: &[&str]| {
        scan::run_selected(host.as_ref(), bundle, context, ids)
    };
    session::run(&mut transport, scan_host, jiff::Timestamp::now).into()
}

#[cfg(not(windows))]
fn platform_run(_args: &Args) -> ExitCode {
    eprintln!("rongroi-scan is a Windows program; it cannot run on this system.");
    ExitCode::from(EXIT_FAILED)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIPE: &str = r"\\.\pipe\rongroi-0123456789abcdef0123456789abcdef";

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn the_pipe_and_elevate_flags_are_accepted() {
        assert_eq!(
            parse_args(args(&["--pipe", PIPE, "--elevate"])),
            Ok(Args {
                pipe: PIPE.to_owned(),
                elevate: true,
            })
        );
        assert_eq!(
            parse_args(args(&["--pipe", PIPE])),
            Ok(Args {
                pipe: PIPE.to_owned(),
                elevate: false,
            })
        );
    }

    #[test]
    fn a_pipe_name_connect_could_not_have_created_is_refused() {
        for name in [
            r"\\.\pipe\rongroi-0123456789abcdef0123456789abcde",
            r"\\.\pipe\rongroi-0123456789ABCDEF0123456789ABCDEF",
            r"\\server\pipe\rongroi-0123456789abcdef0123456789abcdef",
            r"\\.\pipe\rongroi-0123456789abcdef0123456789abcdef\x",
            "\\.\\pipe\\rongroi-0123456789abcdef0123456789abcdef\n",
        ] {
            let result = parse_args(args(&["--pipe", name]));
            assert_eq!(result, Err(ParseError::PipeName), "{name:?}");
        }
    }

    #[test]
    fn a_missing_pipe_or_unknown_argument_is_refused() {
        assert_eq!(parse_args(args(&[])), Err(ParseError::Pipe));
        assert_eq!(parse_args(args(&["--pipe"])), Err(ParseError::Pipe));
        assert_eq!(parse_args(args(&["--elevate"])), Err(ParseError::Pipe));
        assert_eq!(parse_args(args(&["--pipe", PIPE, "--pipe", PIPE])), Err(ParseError::Pipe));
        assert_eq!(parse_args(args(&["--pipe", PIPE, "--unknown"])), Err(ParseError::Unknown));
        assert_eq!(parse_args(args(&["--pipe", PIPE, "extra"])), Err(ParseError::Unknown));
        let pause = args(&["--pipe", PIPE, "--pause-at-exit"]);
        assert_eq!(parse_args(pause), Err(ParseError::Unknown));
    }

    #[test]
    fn the_elevated_copy_keeps_the_pipe_and_drops_elevate() {
        assert_eq!(elevated_args(args(&["--elevate", "--pipe", PIPE])), args(&["--pipe", PIPE]));
    }

    #[test]
    fn the_elevated_copy_never_waits_at_exit() {
        let forwarded = elevated_args(args(&["--elevate", "--pipe", PIPE]));
        assert!(!forwarded.iter().any(|arg| arg == "--pause-at-exit"));

        let with_pause = elevated_args(args(&["--pause-at-exit", "--elevate", "--pipe", PIPE]));
        assert!(!with_pause.iter().any(|arg| arg == "--pause-at-exit"));
    }

    #[test]
    fn forwarding_the_same_arguments_twice_changes_nothing() {
        let once = elevated_args(args(&["--elevate", "--pipe", PIPE]));
        assert_eq!(elevated_args(once.clone()), once);
    }

    #[test]
    fn a_requested_relaunch_prints_the_requested_line_and_exits_zero() {
        assert_eq!(elevate_report(Ok(())), (r#"{"elevate":"requested"}"#, 0));
    }

    #[test]
    fn a_declined_prompt_prints_the_declined_line_and_exits_three() {
        assert_eq!(elevate_report(Err(ElevateError::Declined)), (r#"{"elevate":"declined"}"#, 3));
    }

    #[test]
    fn a_failed_relaunch_exits_one_and_prints_no_argument_value() {
        const SENTINEL: &str = "SENTINEL-PIPE-0123456789abcdef0123456789abcdef";
        for error in [
            ElevateError::Failed(SENTINEL.to_owned()),
            ElevateError::ExePathUnknown(SENTINEL.to_owned()),
        ] {
            let (line, code) = elevate_report(Err(error));
            assert_eq!(code, EXIT_FAILED);
            let json: serde_json::Value = serde_json::from_str(line).expect("the line is JSON");
            assert_eq!(json["elevate"], "failed");
            assert!(!line.contains(SENTINEL));
            assert!(!line.contains(PIPE));
        }
    }
}
