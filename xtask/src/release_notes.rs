// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask release-notes`: the text of the release page (ADR 0008). English first, then a short Thai
//! section for server staff.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context;
use rongroi_core::bundle::BundleInfo;

use crate::release::{Checksum, ReleaseTag, changelog_section, parse_sums, read_report};

#[derive(clap::Args)]
pub struct Args {
    /// The release tag.
    tag: String,
    /// JSON written by the built CLI with `scan --json`.
    #[arg(long)]
    report: PathBuf,
    /// `SHA256SUMS` written by `release-verify`.
    #[arg(long)]
    sums: PathBuf,
    /// Full SHA of the tagged commit.
    #[arg(long)]
    commit: String,
    /// Link to the workflow run that built the files.
    #[arg(long)]
    run_url: String,
    /// `owner/name` of the repository.
    #[arg(long, default_value = "aeterna/aeterna-rongroi")]
    repo: String,
    /// Where to write the notes.
    #[arg(long)]
    out: PathBuf,
}

pub fn run(root: &Path, args: &Args) -> anyhow::Result<()> {
    let tag = ReleaseTag::parse(&args.tag)?;
    let changelog =
        std::fs::read_to_string(root.join("CHANGELOG.md")).context("reading CHANGELOG.md")?;
    let section = changelog_section(&changelog, &tag.version)?;
    let report = read_report(&args.report)?;
    let sums = std::fs::read_to_string(&args.sums)
        .with_context(|| format!("reading {}", args.sums.display()))?;
    let files = parse_sums(&sums)?;
    let notes = render(&Notes {
        tag: &tag,
        changes: &section.body,
        files: &files,
        bundle: &report.header.rules_bundle,
        commit: &args.commit,
        run_url: &args.run_url,
        repo: &args.repo,
    });
    std::fs::write(&args.out, &notes).with_context(|| format!("writing {}", args.out.display()))?;
    println!(
        "release-notes: wrote {} ({} bytes)",
        args.out.display(),
        notes.len()
    );
    Ok(())
}

/// Everything the release page text is built from.
struct Notes<'a> {
    tag: &'a ReleaseTag,
    changes: &'a str,
    files: &'a [Checksum],
    bundle: &'a BundleInfo,
    commit: &'a str,
    run_url: &'a str,
    repo: &'a str,
}

fn render(notes: &Notes<'_>) -> String {
    let version = &notes.tag.version;
    let changes = notes.changes;
    let repo = notes.repo;
    let commit = notes.commit;
    let run_url = notes.run_url;
    let schema = notes.bundle.schema_version;
    let rule_count = notes.bundle.rule_count;
    let bundle_sha256 = &notes.bundle.sha256;
    let short_commit = commit.get(..7).unwrap_or(commit);
    let rehearsal = notes.tag.rc.map_or_else(String::new, |rc| {
        format!("> **Rehearsal build (rc.{rc}).** Not for use on players' machines.\n\n")
    });
    let mut rows = String::new();
    for file in notes.files {
        let _ = writeln!(
            rows,
            "| `{}` | {} | `{}` |",
            file.name,
            describe(&file.name),
            file.sha256
        );
    }
    let example = notes
        .files
        .iter()
        .find(|file| !file.name.contains("-cli-"))
        .or_else(|| notes.files.first())
        .map_or("<file>", |file| file.name.as_str());

    format!(
        "{rehearsal}> **Pre-alpha.** aeterna-rongroi shows evidence for a person to judge. It never proves that a PC is clean.

## Changes

{changes}

## Downloads

Windows 10 22H2 or Windows 11, x64. There is no installer: download a file and run it.

| File | What it is | SHA-256 |
|---|---|---|
{rows}
`SHA256SUMS` lists the same hashes. The `.cdx.json` files are CycloneDX software bills of materials.

## Rules bundle

Rule format {schema} · {rule_count} rule(s) · SHA-256 `{bundle_sha256}`. The report header shows the same values.

## Verify before you trust a result

1. In PowerShell, in the download folder: `Get-FileHash .\\{example}` — the hash must match `SHA256SUMS`.
2. With the GitHub CLI: `gh attestation verify {example} --repo {repo}`.
3. The program shows version {version} and no **UNOFFICIAL BUILD** banner.

If any of these checks fails, do not rely on the result.

## Windows SmartScreen

These files are not code-signed yet (see [GOVERNANCE.md](https://github.com/{repo}/blob/main/GOVERNANCE.md)), so Windows may warn before running them. Check the hash first.

## ภาษาไทย

- โหลดไฟล์ exe แล้วเปิดได้เลย ไม่ต้องติดตั้ง · รุ่น CLI ไม่ใช้ WebView2
- ตรวจไฟล์ก่อนใช้: `Get-FileHash` ต้องตรงกับ `SHA256SUMS` และต้องไม่มีป้าย **UNOFFICIAL BUILD** — ถ้าไม่ตรง อย่าเชื่อผลตรวจนั้น
- ไฟล์ยังไม่ได้เซ็นโค้ด Windows SmartScreen อาจขึ้นเตือนตอนเปิด
- ผลตรวจเป็นหลักฐานประกอบให้คนตัดสิน ไม่ใช่คำตัดสินว่าเครื่องนี้โกงหรือไม่

---

Built from commit [`{short_commit}`](https://github.com/{repo}/commit/{commit}) by [this workflow run]({run_url}).
"
    )
}

fn describe(name: &str) -> &'static str {
    if name.contains("-cli-") {
        "Command line (does not use WebView2)"
    } else {
        "Desktop app (uses Microsoft WebView2)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<Checksum> {
        vec![
            Checksum {
                sha256: "a".repeat(64),
                name: "aeterna-rongroi-0.1.0-windows-x64.exe".to_owned(),
            },
            Checksum {
                sha256: "b".repeat(64),
                name: "aeterna-rongroi-cli-0.1.0-windows-x64.exe".to_owned(),
            },
        ]
    }

    fn bundle() -> BundleInfo {
        BundleInfo {
            schema_version: 1,
            sha256: "c".repeat(64),
            rule_count: 1,
        }
    }

    fn notes_for(tag: &str) -> String {
        let tag = ReleaseTag::parse(tag).unwrap();
        render(&Notes {
            tag: &tag,
            changes: "### Added\n- First release.",
            files: &files(),
            bundle: &bundle(),
            commit: "0123456789abcdef0123456789abcdef01234567",
            run_url: "https://github.com/aeterna/aeterna-rongroi/actions/runs/1",
            repo: "aeterna/aeterna-rongroi",
        })
    }

    #[test]
    fn notes_for_a_release() {
        insta::assert_snapshot!(notes_for("v2026.09.06-0.1.0"));
    }

    #[test]
    fn a_rehearsal_says_so_first() {
        let notes = notes_for("v2026.09.06-0.1.0-rc.1");
        assert!(
            notes.starts_with("> **Rehearsal build (rc.1).**"),
            "{notes}"
        );
    }

    #[test]
    fn a_release_does_not_mention_a_rehearsal() {
        assert!(!notes_for("v2026.09.06-0.1.0").contains("Rehearsal"));
    }
}
