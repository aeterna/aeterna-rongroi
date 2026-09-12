// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `FILETIME` conversion, which is arithmetic on a `u64` rather than a byte format.
//!
//! It earns a target of its own because it has already produced one real panic: a `FILETIME` of
//! `u64::MAX` tripped an assertion inside jiff-core before `Timestamp::from_nanosecond` could return
//! its `Result` (ADR 0013). The range check that fixed it is pinned to jiff's own `MIN`/`MAX`
//! constants, so this target is what notices if a future jiff upgrade moves them. cargo-fuzz builds
//! with debug assertions on by default, which is the build in which that class of defect fires.
//!
//! Seeds: `fixtures/parsers/bam/`, because a BAM value's first eight bytes are exactly this
//! little-endian `FILETIME` — the same files the L0 tests read, rather than a second set of sample
//! bytes for this target alone (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Little-endian, matching how a BAM value stores it, so that the BAM fixtures are meaningful
    // seeds here and a mutation of one stays a plausible FILETIME.
    let Some(head) = data.first_chunk::<8>() else {
        return;
    };
    // `None` — a value outside the representable range — is a correct answer. The bug this target
    // looks for is a panic, an abort or a hang.
    let _ = rongroi_parsers::filetime::to_timestamp(u64::from_le_bytes(*head));
});
