// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The live Windows host. The only crate that calls Windows APIs and the only one allowed `unsafe`.
//! On other platforms it reads nothing; only the parts of [`elevate`] that need no Windows API compile.

#[cfg(windows)]
mod live;

#[cfg(windows)]
pub use live::LiveHost;

#[cfg(windows)]
pub mod filesystem;

pub mod account;

pub mod boot_time;

pub mod device;

pub mod dialog;
pub mod save_dialog;

mod drive_map;

pub mod elevate;

pub mod event_log;

pub mod firmware;

pub mod process;

pub mod relaunch;

// Not `cfg(windows)`: the parser is pure Rust, so its tests run on every platform. The Windows live
// host calls it through `link_target` (ADR 0091 section 2); on other platforms it has no caller, so the
// dead-code allow stays for that build only.
#[cfg_attr(not(windows), allow(dead_code))]
mod reparse;

pub mod signature;

pub mod splash;

pub mod system_integrity;

pub mod tpm;

pub mod usn_journal;
