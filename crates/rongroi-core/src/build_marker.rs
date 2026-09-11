// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// This file is shared by `build.rs` (via `include!`) and by `provenance.rs`, so the marker the build embeds
// and the marker `cargo xtask release-verify` searches for are written by the same function.

/// Start of the build marker text embedded in every binary (ADR 0007).
pub const BUILD_MARKER_PREFIX: &str = "aeterna-rongroi build marker: ";

/// The build marker text for a build made with these values of `RONGROI_OFFICIAL_BUILD` and `RONGROI_COMMIT`.
pub fn build_marker(official_flag: Option<&str>, commit: Option<&str>) -> String {
    format!(
        "{BUILD_MARKER_PREFIX}official={};commit={};",
        official_flag.unwrap_or(""),
        commit.unwrap_or("")
    )
}
