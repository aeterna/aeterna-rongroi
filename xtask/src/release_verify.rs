// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask release-verify`: the built executables are the official build of the tagged commit; only then
//! is `SHA256SUMS` written from them (ADR 0008).

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use rongroi_core::provenance::{Provenance, sha256_hex};

use crate::release::{Checksum, ReleaseTag, format_sums, read_report};

#[derive(clap::Args)]
pub struct Args {
    /// The release tag being built.
    tag: String,
    /// JSON written by the built CLI with `scan --json`.
    #[arg(long)]
    report: PathBuf,
    /// The built CLI, already under its release name.
    #[arg(long)]
    cli: PathBuf,
    /// The built desktop app, already under its release name.
    #[arg(long)]
    desktop: PathBuf,
    /// Full SHA of the tagged commit.
    #[arg(long)]
    commit: String,
    /// Where to write `SHA256SUMS`.
    #[arg(long)]
    sums: PathBuf,
}

pub fn run(args: &Args) -> anyhow::Result<()> {
    let tag = ReleaseTag::parse(&args.tag)?;
    if !is_full_sha(&args.commit) {
        bail!(
            "release-verify: `{}` is not a full 40-character lowercase commit SHA",
            args.commit
        );
    }
    let report = read_report(&args.report)?;
    let cli = read(&args.cli)?;
    let desktop = read(&args.desktop)?;
    let cli_sha256 = sha256_hex(&cli);

    let mut problems = provenance_problems(
        &report.header.provenance,
        &tag.version,
        &args.commit,
        &cli_sha256,
    );
    if !contains_bytes(&desktop, args.commit.as_bytes()) {
        problems.push(format!(
            "{} does not contain the commit {}: RONGROI_COMMIT did not reach the desktop build",
            args.desktop.display(),
            args.commit
        ));
    }
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("error: {problem}");
        }
        bail!("release-verify: {} problem(s)", problems.len());
    }

    let sums = format_sums(&[
        Checksum {
            sha256: cli_sha256,
            name: file_name(&args.cli)?,
        },
        Checksum {
            sha256: sha256_hex(&desktop),
            name: file_name(&args.desktop)?,
        },
    ]);
    std::fs::write(&args.sums, &sums)
        .with_context(|| format!("writing {}", args.sums.display()))?;
    print!("{sums}");
    println!("release-verify: {} ok", args.tag);
    Ok(())
}

/// Ways the CLI's own report shows that it is not the official build of this tag.
fn provenance_problems(
    provenance: &Provenance,
    version: &str,
    commit: &str,
    cli_sha256: &str,
) -> Vec<String> {
    let mut problems = Vec::new();
    if !provenance.official {
        problems.push(
            "the CLI reports an unofficial build: RONGROI_OFFICIAL_BUILD=1 did not reach the build"
                .to_owned(),
        );
    }
    if provenance.version != version {
        problems.push(format!(
            "the CLI reports version {}, the tag has {version}",
            provenance.version
        ));
    }
    if provenance.commit.as_deref() != Some(commit) {
        problems.push(format!(
            "the CLI reports commit {:?}, the tag points at {commit}",
            provenance.commit
        ));
    }
    if provenance.exe_sha256.as_deref() != Some(cli_sha256) {
        problems.push(format!(
            "the CLI hashed itself as {:?}, the file's SHA-256 is {cli_sha256}",
            provenance.exe_sha256
        ));
    }
    problems
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn is_full_sha(text: &str) -> bool {
    text.len() == 40
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn read(path: &Path) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn file_name(path: &Path) -> anyhow::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .with_context(|| format!("{} has no file name", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn hash(c: &str) -> String {
        c.repeat(64)
    }

    fn official() -> Provenance {
        Provenance::from_parts(Some("1"), "0.1.0", Some(COMMIT), Some(hash("f")))
    }

    #[test]
    fn the_official_build_of_the_tag_passes() {
        assert!(provenance_problems(&official(), "0.1.0", COMMIT, &hash("f")).is_empty());
    }

    #[test]
    fn an_unofficial_build_fails() {
        let unofficial = Provenance::from_parts(None, "0.1.0", Some(COMMIT), Some(hash("f")));
        let problems = provenance_problems(&unofficial, "0.1.0", COMMIT, &hash("f"));
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("unofficial build"), "{problems:?}");
    }

    #[test]
    fn wrong_version_commit_or_hash_each_fail() {
        let other_commit = "1".repeat(40);
        assert_eq!(
            provenance_problems(&official(), "0.2.0", &other_commit, &hash("e")).len(),
            3
        );
        let no_commit = Provenance::from_parts(Some("1"), "0.1.0", None, Some(hash("f")));
        assert_eq!(
            provenance_problems(&no_commit, "0.1.0", COMMIT, &hash("f")).len(),
            1
        );
    }

    #[test]
    fn finds_the_commit_inside_a_binary() {
        let binary = [
            b"\x00\x01prefix".as_slice(),
            COMMIT.as_bytes(),
            b"\xffsuffix",
        ]
        .concat();
        assert!(contains_bytes(&binary, COMMIT.as_bytes()));
        assert!(!contains_bytes(b"no commit here", COMMIT.as_bytes()));
        assert!(!contains_bytes(&binary, b""));
    }

    #[test]
    fn only_full_lowercase_shas_are_accepted() {
        assert!(is_full_sha(COMMIT));
        assert!(!is_full_sha(&COMMIT[..7]));
        assert!(!is_full_sha(&COMMIT.to_uppercase()));
    }
}
