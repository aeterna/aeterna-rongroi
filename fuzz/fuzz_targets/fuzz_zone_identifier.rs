// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A file's `:Zone.Identifier` stream, read for its zone and download host (ADR 0079 section 2).
//! Seeds: none yet — the L0 tests build the stream's text in code (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Nothing is asserted about the result: malformed text is a typed error, which is a correct
    // answer. The bug this target looks for is a panic, an abort, a hang or an allocation the input
    // chose.
    let _ = rongroi_parsers::zone_identifier::parse(data);
});
