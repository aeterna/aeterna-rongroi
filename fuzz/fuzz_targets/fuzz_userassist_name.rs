// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A UserAssist value name is text written on the machine being checked, and any byte can be in it.
//! There is no seed corpus yet; the target covers every input `from_utf8_lossy` can produce.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Nothing is asserted about the result: ROT13 changes ASCII letters and leaves every other
    // character alone, so every string has an answer. The bug this target looks for is a panic, an
    // abort or a hang.
    let _ = rongroi_parsers::userassist::decode_name(&String::from_utf8_lossy(data));
});
