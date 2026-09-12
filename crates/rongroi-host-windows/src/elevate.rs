// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Restarting this program with administrator rights.
//!
//! Elevation on Windows is a property of a process token, so a process that is already running cannot
//! gain it. The only way is to start a fresh process that has an elevated token and let this one exit
//! (ADR 0012). This module asks Windows to start that process.
//!
//! It reads nothing from the scanned machine, so it is neither a `Host` capability nor a Collector; it
//! is application lifecycle.

/// Why an elevated restart did not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ElevateError {
    /// The person dismissed the Windows consent prompt. A normal outcome, not a fault (ADR 0012).
    #[error("the administrator prompt was declined")]
    Declined,
    /// This program's own path could not be read, so there is nothing to start.
    #[error("could not read this program's own path: {0}")]
    ExePathUnknown(String),
    /// Windows refused the request for any other reason.
    #[error("Windows did not start the elevated program: {0}")]
    Failed(String),
}

/// Builds the parameter string that the elevated process will be started with.
///
/// `ShellExecuteExW` takes the arguments as one string, and the new process splits it again with the
/// rules `CommandLineToArgvW` documents. Quoting is therefore part of the hand-over and is kept here, as
/// plain string logic that is tested on every operating system, rather than inside the `unsafe` call.
pub fn command_line(args: &[String]) -> String {
    let quoted: Vec<String> = args.iter().map(|arg| quote(arg)).collect();
    quoted.join(" ")
}

/// Quotes one argument so that `CommandLineToArgvW` hands the new process the same string back.
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0_usize;
    for character in arg.chars() {
        match character {
            // A run of backslashes only needs escaping if a quote turns out to follow it.
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..=(backslashes * 2) {
                    out.push('\\');
                }
                backslashes = 0;
                out.push('"');
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(character);
            }
        }
    }
    // A backslash immediately before the closing quote would escape it instead of ending the argument.
    for _ in 0..backslashes * 2 {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Asks Windows to start this program again with administrator rights, passing it `args`.
///
/// Returns once the relaunch has been *requested*. It does not wait for the new process and it does not
/// end this one; the caller decides when to exit (ADR 0012). Windows shows its consent prompt first, and
/// dismissing that prompt gives [`ElevateError::Declined`] — a normal outcome, not a fault.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn relaunch_elevated(args: &[String]) -> Result<(), ElevateError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use windows::Win32::UI::Shell::{
        SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows::core::PCWSTR;

    /// `HRESULT_FROM_WIN32(ERROR_CANCELLED)` — 1223, what Windows reports when the person dismisses the
    /// consent prompt.
    const HRESULT_ERROR_CANCELLED: i32 = 0x8007_04C7_u32.cast_signed();
    /// `SW_SHOWNORMAL`, written out so this crate does not take the whole
    /// `Win32_UI_WindowsAndMessaging` feature for one constant.
    const SW_SHOWNORMAL: i32 = 1;

    /// A NUL-terminated UTF-16 copy, as the `W` entry points expect.
    fn wide(text: &OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    let exe =
        std::env::current_exe().map_err(|error| ElevateError::ExePathUnknown(error.to_string()))?;
    let Ok(cb_size) = u32::try_from(size_of::<SHELLEXECUTEINFOW>()) else {
        return Err(ElevateError::Failed(
            "SHELLEXECUTEINFOW does not fit in a u32".to_owned(),
        ));
    };

    // These three buffers must outlive the call: the struct only holds pointers into them.
    let file = wide(exe.as_os_str());
    let verb = wide(OsStr::new("runas"));
    let parameters = wide(OsStr::new(&command_line(args)));

    let mut info = SHELLEXECUTEINFOW {
        cbSize: cb_size,
        // NOASYNC: finish the request before returning, because the caller exits straight afterwards.
        // FLAG_NO_UI: hand failures back here instead of letting the shell put up its own dialog.
        fMask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };

    // SAFETY: `info` is a fully initialised `SHELLEXECUTEINFOW` whose `cbSize` is its own size, and the
    // three strings it points at are NUL-terminated and owned by this function, so they outlive the
    // call — `SEE_MASK_NOASYNC` means the call is finished when it returns.
    unsafe { ShellExecuteExW(&raw mut info) }.map_err(|error| match error.code().0 {
        HRESULT_ERROR_CANCELLED => ElevateError::Declined,
        _ => ElevateError::Failed(error.message()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_argument_list_is_an_empty_parameter_string() {
        assert_eq!(command_line(&[]), "");
    }

    #[test]
    fn a_plain_argument_is_passed_through_unquoted() {
        assert_eq!(command_line(&["scan".to_owned()]), "scan");
    }

    #[test]
    fn arguments_are_separated_by_one_space() {
        assert_eq!(
            command_line(&["scan".to_owned(), "--mode".to_owned(), "ss".to_owned()]),
            "scan --mode ss"
        );
    }

    #[test]
    fn an_argument_containing_a_space_is_quoted() {
        assert_eq!(command_line(&["a b".to_owned()]), r#""a b""#);
    }

    #[test]
    fn an_argument_containing_a_tab_is_quoted() {
        assert_eq!(command_line(&["a\tb".to_owned()]), "\"a\tb\"");
    }

    #[test]
    fn a_literal_quote_is_escaped() {
        assert_eq!(command_line(&[r#"say "hi""#.to_owned()]), r#""say \"hi\"""#);
    }

    #[test]
    fn backslashes_before_a_quote_are_doubled() {
        // Only the backslashes that precede a quote are doubled; the quote itself is then escaped.
        assert_eq!(command_line(&[r#"a\"b"#.to_owned()]), r#""a\\\"b""#);
    }

    #[test]
    fn a_backslash_that_precedes_nothing_is_left_alone() {
        assert_eq!(command_line(&[r"a\b c".to_owned()]), r#""a\b c""#);
    }

    #[test]
    fn trailing_backslashes_of_a_quoted_argument_are_doubled() {
        // Without doubling, the last backslash would escape the closing quote instead of ending the path.
        assert_eq!(
            command_line(&[r"c:\program files\".to_owned()]),
            r#""c:\program files\\""#
        );
    }

    #[test]
    fn an_empty_argument_survives_as_an_empty_quoted_string() {
        assert_eq!(command_line(&[String::new()]), r#""""#);
    }
}
