// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask loldrivers`: rebuilds the vulnerable-driver data file from a `LOLDrivers` checkout (ADR 0048).
//!
//! It reads `yaml/*.yaml` of a checkout someone already made at the commit the data file's
//! `PROVENANCE.md` names, and nothing else. Neither this task nor the program fetches the list.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

/// The data file, relative to the repository root.
pub const DATA_FILE: &str =
    "rules/driver_service/vulnerable-driver/loldrivers-listed/loldrivers-vulnerable-drivers.csv";

const HEADER: &str = "sha256,loldrivers_id,file_name";
const CATEGORY: &str = "vulnerable driver";

#[derive(clap::Args)]
pub struct Args {
    /// A `LOLDrivers` checkout whose `yaml/` folder holds one file per driver.
    #[arg(long)]
    checkout: PathBuf,
    /// Do not write anything; fail if the committed file differs from what the checkout produces.
    #[arg(long)]
    check: bool,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Category")]
    category: String,
    #[serde(rename = "Verified", default)]
    verified: Option<serde_json::Value>,
    #[serde(rename = "KnownVulnerableSamples", default)]
    samples: Option<Vec<Sample>>,
}

#[derive(Deserialize)]
struct Sample {
    #[serde(rename = "SHA256", default)]
    sha256: Option<serde_json::Value>,
    #[serde(rename = "Filename", default)]
    filename: Option<serde_json::Value>,
    #[serde(rename = "OriginalFilename", default)]
    original_filename: Option<serde_json::Value>,
}

pub fn run(root: &Path, args: &Args) -> anyhow::Result<()> {
    let csv = build(&args.checkout.join("yaml"))?;
    let rows = csv.lines().count().saturating_sub(1);
    let target = root.join(DATA_FILE);
    if args.check {
        let committed = std::fs::read_to_string(&target)
            .with_context(|| format!("reading {DATA_FILE}"))?
            .replace("\r\n", "\n");
        if committed != csv {
            bail!(
                "{DATA_FILE} differs from what the checkout produces; run `cargo xtask loldrivers --checkout <dir>`"
            );
        }
        println!("loldrivers: {DATA_FILE} matches the checkout ({rows} rows)");
    } else {
        std::fs::write(&target, &csv).with_context(|| format!("writing {DATA_FILE}"))?;
        println!("loldrivers: wrote {DATA_FILE} ({rows} rows)");
    }
    Ok(())
}

/// The data file's text for every `*.yaml` directly inside `yaml_dir`.
pub fn build(yaml_dir: &Path) -> anyhow::Result<String> {
    let mut paths = std::fs::read_dir(yaml_dir)
        .with_context(|| format!("listing {}", yaml_dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.retain(|path| path.extension().is_some_and(|ext| ext == "yaml"));
    paths.sort();
    if paths.is_empty() {
        bail!("{} holds no .yaml file", yaml_dir.display());
    }
    let mut entries = Vec::with_capacity(paths.len());
    for path in &paths {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let entry: Entry =
            serde_saphyr::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        entries.push(entry);
    }
    rows(&entries)
}

fn rows(entries: &[Entry]) -> anyhow::Result<String> {
    let mut by_hash: BTreeMap<String, (String, String)> = BTreeMap::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.category == CATEGORY && is_true(entry.verified.as_ref()))
    {
        for sample in entry.samples.iter().flatten() {
            let Some(hash) = sample
                .sha256
                .as_ref()
                .and_then(serde_json::Value::as_str)
                .map(|hash| hash.trim().to_ascii_lowercase())
                .filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            else {
                continue;
            };
            let name = [&sample.filename, &sample.original_filename]
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .find(|name| !name.is_empty())
                .unwrap_or_default();
            if name.contains([',', '"', '\n', '\r']) {
                bail!(
                    "entry {}: file name {name:?} cannot be written in one CSV field",
                    entry.id
                );
            }
            let keep = by_hash.get(&hash).is_none_or(|(kept, _)| entry.id < *kept);
            if keep {
                by_hash.insert(hash, (entry.id.clone(), name.to_owned()));
            }
        }
    }
    let mut csv = format!("{HEADER}\n");
    for (hash, (id, name)) in &by_hash {
        let _ = writeln!(csv, "{hash},{id},{name}");
    }
    Ok(csv)
}

/// `Verified` is `TRUE`, `true` or `True` upstream, sometimes quoted; anything else is not verified.
fn is_true(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(flag)) => *flag,
        Some(serde_json::Value::String(text)) => text.trim().eq_ignore_ascii_case("true"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(yaml: &str) -> Entry {
        serde_saphyr::from_str(yaml).unwrap()
    }

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn only_verified_vulnerable_drivers_with_a_sha256_become_rows() {
        let entries = [
            entry(&format!(
                "Id: id-2\nCategory: vulnerable driver\nVerified: 'TRUE'\nKnownVulnerableSamples:\n  - SHA256: {}\n    Filename: Two.sys\n  - MD5: 00\n    Filename: nohash.sys\n",
                A.to_ascii_uppercase()
            )),
            entry(&format!(
                "Id: id-3\nCategory: vulnerable driver\nVerified: FALSE\nKnownVulnerableSamples:\n  - SHA256: {B}\n"
            )),
            entry(&format!(
                "Id: id-4\nCategory: malicious\nVerified: TRUE\nKnownVulnerableSamples:\n  - SHA256: {B}\n"
            )),
            entry(
                "Id: id-5\nCategory: vulnerable driver\nVerified: true\nKnownVulnerableSamples:\n",
            ),
        ];
        assert_eq!(
            rows(&entries).unwrap(),
            format!("{HEADER}\n{A},id-2,Two.sys\n")
        );
    }

    #[test]
    fn a_hash_in_several_entries_keeps_the_first_id_and_a_missing_name_falls_back() {
        let entries = [
            entry(&format!(
                "Id: id-9\nCategory: vulnerable driver\nVerified: TRUE\nKnownVulnerableSamples:\n  - SHA256: {A}\n    Filename: late.sys\n"
            )),
            entry(&format!(
                "Id: id-1\nCategory: vulnerable driver\nVerified: TRUE\nKnownVulnerableSamples:\n  - SHA256: {A}\n    Filename: ''\n    OriginalFilename: early.sys\n  - SHA256: {B}\n"
            )),
        ];
        assert_eq!(
            rows(&entries).unwrap(),
            format!("{HEADER}\n{A},id-1,early.sys\n{B},id-1,\n")
        );
    }

    #[test]
    fn a_file_name_that_would_break_a_csv_field_stops_the_build() {
        let entries = [entry(&format!(
            "Id: id-1\nCategory: vulnerable driver\nVerified: TRUE\nKnownVulnerableSamples:\n  - SHA256: {A}\n    Filename: 'a,b.sys'\n"
        ))];
        assert!(rows(&entries).is_err());
    }
}
