// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Embeds the rules source tree (`/rules`) into the crate as the rules bundle.
//! Rules are parsed and validated at runtime by `Bundle::embedded()`; a unit test and
//! `cargo xtask check-rules` make an invalid bundle fail CI before it can ship.

include!("src/source_tree.rs");
include!("src/build_marker.rs");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let rules_dir = manifest_dir.join("../../rules");
    println!("cargo:rerun-if-changed={}", rules_dir.display());
    println!("cargo:rerun-if-env-changed=RONGROI_OFFICIAL_BUILD");
    println!("cargo:rerun-if-env-changed=RONGROI_COMMIT");

    // One text carries both values, so a binary that contains it was built with both (ADR 0007, ADR 0008).
    let official_flag = build_env("RONGROI_OFFICIAL_BUILD");
    let commit = build_env("RONGROI_COMMIT");
    let marker = build_marker(official_flag.as_deref(), commit.as_deref());
    println!("cargo:rustc-env=RONGROI_BUILD_MARKER={marker}");

    let bundle = collect_bundle_json(&rules_dir)?;
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("rules_bundle.json");
    std::fs::write(out, bundle)?;
    Ok(())
}

/// A build variable, or `None` when it is unset, not UTF-8, or would break the `cargo:` line.
fn build_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.contains(['\n', '\r']))
}
