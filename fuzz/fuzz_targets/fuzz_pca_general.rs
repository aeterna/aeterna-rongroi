// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `PcaGeneralDb0.txt` / `PcaGeneralDb1.txt` are CP-1252 text whose layout is reverse-engineered, so
//! the parser names no field and accepts any field count. Seeds: `fixtures/parsers/pca-general/`,
//! the same files the L0 tests read (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // See fuzz_pca_app_launch.rs: rejected lines and a refused UTF-16 file are correct answers. The
    // bug this target looks for is a panic, an abort or a hang.
    let _ = rongroi_parsers::pca::parse_general_db(data);
});
