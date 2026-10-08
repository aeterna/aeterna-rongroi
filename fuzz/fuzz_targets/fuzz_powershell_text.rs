// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A PowerShell history file, a script block's text and a command line are text a person or a program
//! wrote on the machine being checked, and an encoded command inside one is decoded (ADR 0064). Seeds:
//! `fixtures/parsers/powershell-text/`, the same files the L0 tests read (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Nothing is asserted about the result: every input has a classification. The bug this target
    // looks for is a panic, an abort, a hang or an allocation the input chose.
    let _ = rongroi_parsers::powershell_text::parse_history(data);
    let _ = rongroi_parsers::powershell_text::classify(&String::from_utf8_lossy(data));
});
