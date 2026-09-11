// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Core of aeterna-rongroi: the data model, the rule format, the evidence engine and the views.
//!
//! This crate knows nothing about Windows. Collectors turn a host into [`model::CollectorRun`]s,
//! [`engine::evaluate`] turns runs and the embedded [`bundle::Bundle`] into a [`model::Report`],
//! and [`view::for_mode`] decides what a Self or SS view may show.

pub mod bundle;
pub mod engine;
pub mod model;
pub mod provenance;
pub mod rules;
pub mod view;

/// Reads the rules source tree from disk. Enabled only for `cargo xtask`; shipped binaries use
/// [`bundle::Bundle::embedded`] and cannot load rules from anywhere else.
#[cfg(feature = "source-tree")]
pub mod source_tree;
