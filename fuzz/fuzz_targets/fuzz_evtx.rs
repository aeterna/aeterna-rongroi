// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! An `.evtx` file is read from `%SystemRoot%\System32\winevt\Logs` on the machine being checked, and
//! of the six targets here this one covers by far the most third-party code: `evtx` brings a binary
//! XML decoder, a chunk reader, per-chunk string tables and a template cache, and under it an
//! unmaintained `encoding` crate decodes 8-bit strings out of the same attacker-controlled bytes.
//!
//! That is the second half of the argument ADR 0018 made for taking the dependency at all — the first
//! being that writing a binary XML decoder here would be the larger risk — and the ignore entry
//! `deny.toml` carries for RUSTSEC-2021-0153 names this target as one of the things that bounds it.
//! So this target is not decoration: it is the thing that was promised in exchange.
//!
//! Seeds: `fixtures/evtx/`, the same files the L0 tests read (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Nothing is asserted about the result. Bytes that are not an Event Log, a chunk whose header is
    // damaged, a record whose binary XML does not decode, and a timestamp that names no instant are
    // all typed `ParseError`s or accounted-for rejections, and all correct answers. The bug this
    // target looks for is a panic, an abort or a hang — a hang included, because a chunk reader that
    // is told how many records to expect is exactly the shape that loops on a crafted file.
    let _ = rongroi_parsers::evtx::records(data);
});
