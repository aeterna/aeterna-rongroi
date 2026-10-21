// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A file's whole bytes, read for its content kind, trailing data and embedded PE (ADR 0078
//! section 8). Seeds: the fixture directories under `fixtures/parsers/` that the L0 tests read
//! (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Nothing is asserted about the result: every input is `Ok` by the parser's contract, and a
    // kind of `unknown` is a correct answer. The bug this target looks for is a panic, an abort or
    // a hang.
    let _ = rongroi_parsers::content_kind::parse(data);
});
