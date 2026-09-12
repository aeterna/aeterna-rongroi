// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Collectors read one kind of artifact from a [`Host`] and report what they saw.
//! Rules for writing one are in `crates/rongroi-collectors/AGENTS.md` and `CONVENTIONS.md` §3.

pub mod failure;
pub mod fivem_dir;
pub mod pca;
pub mod posture;
pub mod prefetch;
pub mod process;
pub mod scan;

use rongroi_core::model::CollectorRun;
use rongroi_host::Host;

/// Reads one kind of artifact. Implementations must be read-only and must never panic.
pub trait Collector {
    /// Stable id, equal to the `collector` field of the rules that read it.
    fn id(&self) -> &'static str;
    /// Looks at the host.
    fn collect(&self, host: &dyn Host) -> CollectorRun;
}

/// Every collector in this build.
pub fn all() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(fivem_dir::FivemDir),
        Box::new(pca::Pca),
        Box::new(posture::Posture),
        Box::new(prefetch::Prefetch),
        Box::new(process::Process),
    ]
}
