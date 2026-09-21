// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask loldrivers`: rebuilds the vulnerable-driver data file from a `LOLDrivers` checkout (ADR 0048).
//!
//! It reads `yaml/*.yaml` of a checkout someone already made at the commit the data file's
//! `PROVENANCE.md` names, and nothing else. Before it reads anything under `yaml/`, it checks that the
//! checkout is actually at that commit — `git -C <checkout> rev-parse HEAD`, the one git command this
//! task runs, read from the checkout's own `.git`, never from a remote (Minor 1 of the PR 3 review).
//! Neither this task nor the program fetches the list.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

/// The data file, relative to the repository root.
pub const DATA_FILE: &str =
    "rules/driver_service/vulnerable-driver/loldrivers-listed/loldrivers-vulnerable-drivers.csv";

/// `PROVENANCE.md`, beside the data file, relative to the repository root. Names the commit a checkout
/// must be at.
pub const PROVENANCE_FILE: &str =
    "rules/driver_service/vulnerable-driver/loldrivers-listed/PROVENANCE.md";

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
    /// The Authenticode hash upstream computes, which this program does not (ADR 0046). Read only to
    /// count how many samples with no usable `SHA256` carry one instead (Minor 3 of the PR 3 review) —
    /// never written to the data file.
    #[serde(rename = "Authentihash", default)]
    authentihash: Option<Authentihash>,
}

#[derive(Deserialize)]
struct Authentihash {
    #[serde(rename = "SHA256", default)]
    sha256: Option<serde_json::Value>,
}

/// Everything [`rows`] and [`build`] compute, beyond the CSV text itself, so `run` can print every
/// figure `PROVENANCE.md` states and the update sentence can name them all (Minor 3 of the PR 3
/// review).
#[derive(Debug)]
pub struct Counts {
    /// The data file's text.
    pub csv: String,
    /// Distinct verified hashes written as rows.
    pub rows: usize,
    /// `.yaml` files read.
    pub files: usize,
    /// Distinct hashes that appear in a sample of an unverified `vulnerable driver` entry and in no
    /// verified one, so they are left out of the data file.
    pub dropped_unverified: usize,
    /// Samples of *verified* `vulnerable driver` entries with no usable `SHA256`.
    pub verified_no_sha256: usize,
    /// Of `verified_no_sha256`, how many carry a non-empty `Authentihash.SHA256`.
    pub verified_no_sha256_with_authentihash: usize,
    /// Samples of every `vulnerable driver` entry, verified or not, with no usable `SHA256`.
    pub all_no_sha256: usize,
    /// Of `all_no_sha256`, how many carry a non-empty `Authentihash.SHA256`.
    pub all_no_sha256_with_authentihash: usize,
}

pub fn run(root: &Path, args: &Args) -> anyhow::Result<()> {
    let provenance_path = root.join(PROVENANCE_FILE);
    let provenance_text = std::fs::read_to_string(&provenance_path)
        .with_context(|| format!("reading {PROVENANCE_FILE}"))?;
    let expected_commit = provenance_commit(&provenance_text)?;
    let actual_commit = git_head(&args.checkout)?;
    if actual_commit != expected_commit {
        bail!(
            "{PROVENANCE_FILE} names commit {expected_commit}, but `git -C {} rev-parse HEAD` says {actual_commit}; check out {expected_commit} before running this task",
            args.checkout.display()
        );
    }

    let counts = build(&args.checkout.join("yaml"))?;
    let target = root.join(DATA_FILE);
    if args.check {
        let committed = std::fs::read_to_string(&target)
            .with_context(|| format!("reading {DATA_FILE}"))?
            .replace("\r\n", "\n");
        if committed != counts.csv {
            bail!(
                "{DATA_FILE} differs from what the checkout produces; run `cargo xtask loldrivers --checkout <dir>`"
            );
        }
        println!(
            "loldrivers: {DATA_FILE} matches the checkout ({})",
            summary(&counts)
        );
    } else {
        std::fs::write(&target, &counts.csv).with_context(|| format!("writing {DATA_FILE}"))?;
        println!("loldrivers: wrote {DATA_FILE} ({})", summary(&counts));
    }
    Ok(())
}

/// The one line of figures both branches of `run` print, so `--check` and a rebuild always agree with
/// each other and with what `PROVENANCE.md`'s update sentence must name (Minor 3 of the PR 3 review).
fn summary(counts: &Counts) -> String {
    format!(
        "{rows} rows, {files} files read, {dropped} hash(es) dropped as unverified, \
         {vno} verified sample(s) without a usable SHA256 ({vauth} with an Authentihash), \
         {ano} across all vulnerable-driver entries ({aauth} with an Authentihash)",
        rows = counts.rows,
        files = counts.files,
        dropped = counts.dropped_unverified,
        vno = counts.verified_no_sha256,
        vauth = counts.verified_no_sha256_with_authentihash,
        ano = counts.all_no_sha256,
        aauth = counts.all_no_sha256_with_authentihash,
    )
}

/// The commit `PROVENANCE.md` names, read from its `Commit` table row (a backticked commit between two
/// pipe characters). Pure text parsing over the file's own content — no git, no filesystem — so it is
/// unit-tested directly rather than only through `run` (Minor 1 of the PR 3 review).
fn provenance_commit(text: &str) -> anyhow::Result<String> {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("| Commit"))
        .with_context(|| format!("no `| Commit |` row in {PROVENANCE_FILE}"))?;
    let commit = line
        .split('`')
        .nth(1)
        .filter(|text| !text.is_empty())
        .with_context(|| {
            format!("`| Commit |` row in {PROVENANCE_FILE} has no backticked commit: {line:?}")
        })?;
    Ok(commit.to_owned())
}

/// `git -C <checkout> rev-parse HEAD`, trimmed — the checkout's own recorded commit, read locally. The
/// only git command this task (or the program) runs; see the module doc.
fn git_head(checkout: &Path) -> anyhow::Result<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(["rev-parse", "HEAD"])
        .output()
        .with_context(|| format!("running git rev-parse HEAD in {}", checkout.display()))?;
    if !output.status.success() {
        bail!(
            "git rev-parse HEAD in {} failed: {}",
            checkout.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let head = String::from_utf8(output.stdout)
        .with_context(|| format!("git rev-parse HEAD in {} was not UTF-8", checkout.display()))?;
    Ok(head.trim().to_owned())
}

/// The data file's text, and its counts, for every `*.yaml` directly inside `yaml_dir`.
pub fn build(yaml_dir: &Path) -> anyhow::Result<Counts> {
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
    let mut counts = rows(&entries)?;
    counts.files = entries.len();
    Ok(counts)
}

fn rows(entries: &[Entry]) -> anyhow::Result<Counts> {
    let mut by_hash: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut unverified_hashes: BTreeSet<String> = BTreeSet::new();
    let mut verified_no_sha256 = 0usize;
    let mut verified_no_sha256_with_authentihash = 0usize;
    let mut all_no_sha256 = 0usize;
    let mut all_no_sha256_with_authentihash = 0usize;

    for entry in entries.iter().filter(|entry| entry.category == CATEGORY) {
        let verified = is_true(entry.verified.as_ref());
        for sample in entry.samples.iter().flatten() {
            let hash = sample_hash(&entry.id, sample.sha256.as_ref())?;
            let Some(hash) = hash else {
                let has_authentihash = has_authentihash_sha256(sample);
                all_no_sha256 += 1;
                if has_authentihash {
                    all_no_sha256_with_authentihash += 1;
                }
                if verified {
                    verified_no_sha256 += 1;
                    if has_authentihash {
                        verified_no_sha256_with_authentihash += 1;
                    }
                }
                continue;
            };
            if !verified {
                unverified_hashes.insert(hash);
                continue;
            }
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
    let dropped_unverified = unverified_hashes
        .iter()
        .filter(|hash| !by_hash.contains_key(*hash))
        .count();

    let mut csv = format!("{HEADER}\n");
    for (hash, (id, name)) in &by_hash {
        let _ = writeln!(csv, "{hash},{id},{name}");
    }
    Ok(Counts {
        rows: by_hash.len(),
        csv,
        files: 0,
        dropped_unverified,
        verified_no_sha256,
        verified_no_sha256_with_authentihash,
        all_no_sha256,
        all_no_sha256_with_authentihash,
    })
}

/// `Verified` is `TRUE`, `true` or `True` upstream, sometimes quoted; anything else is not verified.
fn is_true(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(flag)) => *flag,
        Some(serde_json::Value::String(text)) => text.trim().eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// A sample's validated `SHA256`: `None` for a null or empty field — both present upstream today (48
/// null, 49 empty at `1c60ea1`) — and an error for a value of the wrong shape: a non-empty string that
/// is not 64 hex digits once trimmed, or a value that is not a string or null at all. Silently dropping
/// either shape, as the code before Minor 4 of the PR 3 review did, would let a future upstream typo
/// remove a hash with `--check` still passing against that checkout.
fn sample_hash(
    entry_id: &str,
    value: Option<&serde_json::Value>,
) -> anyhow::Result<Option<String>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            let hash = trimmed.to_ascii_lowercase();
            if hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                Ok(Some(hash))
            } else {
                bail!("entry {entry_id}: SHA256 {text:?} is not 64 hex digits once trimmed");
            }
        }
        Some(other) => bail!("entry {entry_id}: SHA256 is neither a string nor null: {other}"),
    }
}

/// Whether a sample carries a non-empty `Authentihash.SHA256` (Minor 3 of the PR 3 review). Not
/// format-validated — this program never reads it beyond the count — so any non-null, non-empty value
/// counts.
fn has_authentihash_sha256(sample: &Sample) -> bool {
    match sample
        .authentihash
        .as_ref()
        .and_then(|hash| hash.sha256.as_ref())
    {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::String(text)) => !text.trim().is_empty(),
        Some(_) => true,
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
        let c = "c".repeat(64);
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
            // Unquoted `Verified: true`, the one form the upstream data does not use today (Minor 7
            // of the PR 3 review): it must be accepted exactly as the quoted forms are, so it needs a
            // sample and an expected row too, not just an entry nothing reads.
            entry(&format!(
                "Id: id-5\nCategory: vulnerable driver\nVerified: true\nKnownVulnerableSamples:\n  - SHA256: {c}\n    Filename: Five.sys\n"
            )),
        ];
        let counts = rows(&entries).unwrap();
        assert_eq!(
            counts.csv,
            format!("{HEADER}\n{A},id-2,Two.sys\n{c},id-5,Five.sys\n")
        );
        assert_eq!(counts.rows, 2);
        // `id-3` (unverified, `vulnerable driver`) is the only entry with hash `B` in that category —
        // `id-4` shares it but is `malicious`, so it is filtered out before hashes are even collected.
        // `B` is a candidate to drop as unverified, and nothing verified keeps it, so it is dropped.
        assert_eq!(counts.dropped_unverified, 1);
        // `id-2`'s second sample (`MD5: 00`, no `SHA256` field at all) is the one sample here with no
        // usable hash, and it belongs to a verified entry.
        assert_eq!(counts.verified_no_sha256, 1);
        assert_eq!(counts.verified_no_sha256_with_authentihash, 0);
        assert_eq!(counts.all_no_sha256, 1);
        assert_eq!(counts.all_no_sha256_with_authentihash, 0);
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
        let counts = rows(&entries).unwrap();
        assert_eq!(
            counts.csv,
            format!("{HEADER}\n{A},id-1,early.sys\n{B},id-1,\n")
        );
        assert_eq!(counts.rows, 2);
    }

    #[test]
    fn a_file_name_that_would_break_a_csv_field_stops_the_build() {
        let entries = [entry(&format!(
            "Id: id-1\nCategory: vulnerable driver\nVerified: TRUE\nKnownVulnerableSamples:\n  - SHA256: {A}\n    Filename: 'a,b.sys'\n"
        ))];
        assert!(rows(&entries).is_err());
    }

    /// Minor 4 of the PR 3 review: a non-empty `SHA256` that is not 64 hex digits once trimmed must
    /// stop the build loudly, named by the entry it came from, rather than being dropped in silence
    /// the way a null or empty value is.
    #[test]
    fn a_malformed_sha256_stops_the_build_and_names_the_entry() {
        let entries = [entry(
            "Id: id-6\nCategory: vulnerable driver\nVerified: TRUE\nKnownVulnerableSamples:\n  - SHA256: 'not-a-hash'\n",
        )];
        let error = rows(&entries).unwrap_err();
        assert!(error.to_string().contains("id-6"), "{error}");
    }

    /// Minor 4: a `SHA256` that parsed as something other than a string or null — a bare number, here
    /// — is the same silent-drop hazard and must stop the build too.
    #[test]
    fn a_sha256_that_is_not_a_string_or_null_stops_the_build() {
        let entries = [entry(
            "Id: id-7\nCategory: vulnerable driver\nVerified: TRUE\nKnownVulnerableSamples:\n  - SHA256: 12345\n",
        )];
        assert!(rows(&entries).is_err());
    }

    /// Minor 3: the 97/78 vs 17/11 distinction (PROVENANCE.md's "Minor 2" fix) — a sample with no
    /// usable `SHA256` is counted once for its own entry's `verified` status and again in the
    /// across-every-entry totals, and each is paired with whether it carries an `Authentihash`.
    #[test]
    fn samples_without_a_usable_sha256_are_counted_by_verified_status_and_authentihash() {
        let entries = [
            entry(
                "Id: id-10\nCategory: vulnerable driver\nVerified: TRUE\nKnownVulnerableSamples:\n  - SHA256: null\n    Authentihash:\n      SHA256: deadbeef\n",
            ),
            entry(
                "Id: id-11\nCategory: vulnerable driver\nVerified: TRUE\nKnownVulnerableSamples:\n  - SHA256: ''\n",
            ),
            entry(
                "Id: id-12\nCategory: vulnerable driver\nVerified: FALSE\nKnownVulnerableSamples:\n  - SHA256: null\n    Authentihash:\n      SHA256: feedface\n",
            ),
        ];
        let counts = rows(&entries).unwrap();
        assert_eq!(counts.rows, 0);
        assert_eq!(counts.verified_no_sha256, 2);
        assert_eq!(counts.verified_no_sha256_with_authentihash, 1);
        assert_eq!(counts.all_no_sha256, 3);
        assert_eq!(counts.all_no_sha256_with_authentihash, 2);
    }

    /// A hash that appears only in an unverified `vulnerable driver` entry's sample is left out of the
    /// data file and counted as dropped; the same hash also present in a verified entry is not.
    #[test]
    fn a_hash_only_in_an_unverified_entry_is_dropped_and_counted() {
        let entries = [
            entry(&format!(
                "Id: id-20\nCategory: vulnerable driver\nVerified: FALSE\nKnownVulnerableSamples:\n  - SHA256: {A}\n"
            )),
            entry(&format!(
                "Id: id-21\nCategory: vulnerable driver\nVerified: FALSE\nKnownVulnerableSamples:\n  - SHA256: {B}\n"
            )),
            entry(&format!(
                "Id: id-22\nCategory: vulnerable driver\nVerified: TRUE\nKnownVulnerableSamples:\n  - SHA256: {B}\n    Filename: kept.sys\n"
            )),
        ];
        let counts = rows(&entries).unwrap();
        assert_eq!(counts.rows, 1);
        assert_eq!(counts.dropped_unverified, 1);
    }

    #[test]
    fn provenance_commit_reads_the_backticked_sha_from_the_table_row() {
        let text = "# doc\n\n| Field | Value |\n|---|---|\n| Commit | `1c60ea1c8909396fe294c76aaafae4923b6dbea1`, pushed 2026-09-08 |\n| Taken | 2026-09-15 |\n";
        assert_eq!(
            provenance_commit(text).unwrap(),
            "1c60ea1c8909396fe294c76aaafae4923b6dbea1"
        );
    }

    #[test]
    fn provenance_commit_without_a_commit_row_is_an_error() {
        assert!(provenance_commit("# doc\nno such row here\n").is_err());
    }

    #[test]
    fn provenance_commit_with_an_empty_backticked_span_is_an_error() {
        assert!(provenance_commit("| Commit | ``, pushed today |\n").is_err());
    }
}
