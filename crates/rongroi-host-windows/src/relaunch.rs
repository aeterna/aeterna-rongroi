// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Starting this program again with the token it has, for a full scan (ADR 0052).
//!
//! Like [`crate::elevate`] this is application lifecycle, not a Collector: it reads nothing from the
//! scanned machine. The new copy scans from the beginning; this one exits.

/// Starts this program again with `args` and returns once it has started.
///
/// `std::process::Command` starts it with `CreateProcessW` and no token argument (read from the
/// standard library's `sys/process/windows.rs` in Rust 1.98.1), which is the call ADR 0052 measured:
/// a child of an elevated copy is elevated and a child of a standard copy is standard, with no consent
/// prompt, under the default UAC settings. Its standard input, output and error are the null device,
/// so it holds none of this process's handles open.
pub fn relaunch_same_token(args: &[String]) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    std::process::Command::new(exe)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(drop)
}
