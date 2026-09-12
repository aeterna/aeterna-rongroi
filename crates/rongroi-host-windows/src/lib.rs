// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The live Windows host. The only crate that calls Windows APIs and the only one allowed `unsafe`.
//! On other platforms this crate is empty.

#[cfg(windows)]
mod live;

#[cfg(windows)]
pub use live::LiveHost;

#[cfg(windows)]
pub mod filesystem;
