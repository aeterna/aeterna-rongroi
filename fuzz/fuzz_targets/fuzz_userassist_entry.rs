// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A UserAssist entry is attacker-controlled data read from the machine being checked. There is no
//! seed corpus yet, and every length is worth reaching: a short entry is an answer, not a crash.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Nothing is asserted about the value: a short entry is a typed `ParseError`, which is a correct
    // answer, and the parser deliberately accepts any length of at least 72 bytes. The bug this
    // target looks for is a panic, an abort or a hang.
    let _ = rongroi_parsers::userassist::parse_entry(data);
});
