// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A change journal buffer comes from the kernel, but the parser is held to the bar for hostile input
//! all the same: its tests feed it bytes a test wrote, and an unchecked length is how `evtx` hung
//! (ADR 0047). Seeds: `fixtures/parsers/usn/`, the same files the L0 tests read (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Nothing is asserted: a damaged buffer is a typed answer. The bug this target looks for is a
    // panic, an abort or a hang.
    let _ = rongroi_parsers::usn::parse_buffer(data);

    // `match_buffer` gets two fixed targets: one matched by a version 2 parent index and name, and one
    // matched by its own file reference. Nothing is asserted about the matches either.
    let targets = [
        rongroi_parsers::usn::MatchTarget {
            index: 0,
            parent_index_64: 7,
            parent_id_128: [1; 16],
            file: None,
            name: vec![0x61, 0x2E, 0x65],
        },
        rongroi_parsers::usn::MatchTarget {
            index: 1,
            parent_index_64: 0,
            parent_id_128: [0; 16],
            file: Some((9, [0x55; 16])),
            name: Vec::new(),
        },
    ];
    let _ = rongroi_parsers::usn::match_buffer(data, &targets);
});
