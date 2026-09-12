// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Parsers: Windows artifact bytes in, plain Rust structs out.
//!
//! # The contract every parser in this crate holds
//!
//! Every public parsing function takes `&[u8]` and returns `Result<T, `[`error::ParseError`]`>`.
//!
//! - **Pure.** No OS calls, no file paths, no registry keys, no [`rongroi_host::Host`], no clock, no
//!   global state (CONVENTIONS.md §3). A parser is handed bytes that someone else read.
//! - **No panic, ever, on any input.** `unwrap`, `expect`, `panic!` and indexing that can go out of
//!   bounds are denied at workspace level. A malformed artifact is a typed error, never an abort.
//!   Arbitrary bytes are a normal input here, not an exceptional one.
//! - **No knowledge of the evidence model.** These structs know nothing about
//!   `rongroi_core::model`. Turning a parsed struct into an `Observation`, deciding that a missing
//!   artifact is `Unmeasured`, and redacting a path for SS mode are all a collector's job. Keeping
//!   that seam is the reason this is a separate crate (ADR 0013).
//! - **Nothing read is silently dropped.** Bytes whose meaning is not established are kept and handed
//!   back unnamed — see [`bam::BamEntry::unparsed_tail`] — rather than discarded. A parser that drops
//!   what it does not understand stops being auditable.
//! - **A malformed input never loses the whole file.** Where an artifact is a sequence of records, the
//!   records that parsed are returned alongside an account of the ones that did not
//!   ([`pca::PcaFile`]). A tampered or truncated artifact is exactly when the surviving records
//!   matter most.
//!
//! Because of all of the above the whole crate compiles, tests and fuzzes on macOS and Linux as well
//! as Windows, which is what `docs/testing.md`'s L0 row requires.
//!
//! [`rongroi_host::Host`]: https://github.com/aeterna/aeterna-rongroi

pub mod bam;
pub mod error;
pub mod filetime;
