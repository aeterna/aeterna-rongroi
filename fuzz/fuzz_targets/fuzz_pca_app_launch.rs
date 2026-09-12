// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `PcaAppLaunchDic.txt` is CP-1252 text with one record per line, read from the machine being
//! checked. Seeds: `fixtures/parsers/pca-app-launch/`, the same files the L0 tests read (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A line that does not parse is reported in `PcaFile::rejected` and a UTF-16 byte order mark
    // fails the whole file; both are correct answers, so nothing is asserted about the result. The
    // bug this target looks for is a panic, an abort or a hang.
    let _ = rongroi_parsers::pca::parse_app_launch_dic(data);
});
