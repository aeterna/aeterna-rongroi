// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A `.pf` file is read from `%SystemRoot%\Prefetch` on the machine being checked, and it is the one
//! artifact in this crate whose bytes reach a **third-party** decompressor — `prefetch-core` and its
//! Xpress-Huffman decoder. Every other parser here is our own code reading bytes we decode ourselves.
//!
//! That is why this target exists rather than only the four beside it: ADR 0015 accepted a
//! two-month-old dependency with one maintainer on two grounds, and this is the second of them. The
//! first is that the crate is pure and `forbid(unsafe_code)`, so a defect in it is a wrong parse
//! rather than memory corruption; the second is that a fuzz target would be pointed at it.
//!
//! Seeds: `fixtures/prefetch/`, the same files the L0 tests read (ADR 0016).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Nothing is asserted about the record. Bytes that are not a Prefetch container, a compressed
    // payload that does not decode, an SCCA version this parser does not read, and an offset that
    // points past the payload are all typed `ParseError`s and all correct answers. The bug this
    // target looks for is a panic, an abort or a hang — the abort included, because a MAM header
    // declaring a decompressed size the decompressor would reserve up front is refused by `parse`
    // before it is reached, and an allocation failure is not an error any caller could catch.
    let _ = rongroi_parsers::prefetch::parse(data);
});
