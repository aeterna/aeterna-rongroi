// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A scheduled task's XML file is data read from the machine being checked, written by whatever
//! registered the task (ADR 0060). Seeds: `fixtures/parsers/task/`, the same files the L0 tests read
//! (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Nothing is asserted about the result: a document that is not a task is a typed `ParseError`,
    // which is a correct answer. The bug this target looks for is a panic, an abort or a hang.
    let _ = rongroi_parsers::task::parse_task(data);
});
