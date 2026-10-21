// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A PE file's version resource, read for its `OriginalFilename` (ADR 0078 section 8). Seeds: the
//! fixture directories under `fixtures/parsers/` that the L0 tests read (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Nothing is asserted about the result: a file that is not a readable PE, or whose version
    // resource is malformed, is a typed `ParseError`, which is a correct answer. The bug this target
    // looks for is a panic, an abort or a hang.
    let _ = rongroi_parsers::pe_version::original_filename(data);
});
