// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask release-check <tag>`: the release tag, the version manifests and `CHANGELOG.md` agree, and the
//! tagged commit is on `main` (ADR 0008).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

use crate::release::{ReleaseTag, changelog_section};

/// The workspace version: xtask declares `version.workspace = true`.
const WORKSPACE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(clap::Args)]
pub struct Args {
    /// `vYYYY.MM.DD-X.Y.Z` or `vYYYY.MM.DD-X.Y.Z-rc.N`.
    tag: String,
    /// Ref that must contain the tagged commit (`HEAD`).
    #[arg(long, default_value = "origin/main")]
    main_ref: String,
    /// Append `version=` and `prerelease=` lines to this file (the workflow's `$GITHUB_OUTPUT`).
    #[arg(long)]
    github_output: Option<PathBuf>,
}

pub fn run(root: &Path, args: &Args) -> anyhow::Result<()> {
    let tag = ReleaseTag::parse(&args.tag)?;
    let tauri_conf = "apps/desktop/src-tauri/tauri.conf.json";
    let package_json = "apps/desktop/package.json";
    let manifests = [
        (
            "Cargo.toml [workspace.package]",
            WORKSPACE_VERSION.to_owned(),
        ),
        (tauri_conf, json_version(&root.join(tauri_conf))?),
        (package_json, json_version(&root.join(package_json))?),
    ];
    let changelog =
        std::fs::read_to_string(root.join("CHANGELOG.md")).context("reading CHANGELOG.md")?;

    let mut problems = version_problems(&tag, &manifests);
    problems.extend(changelog_problem(&tag, &changelog));
    if !is_ancestor(root, "HEAD", &args.main_ref)? {
        problems.push(format!("the tagged commit is not on {}", args.main_ref));
    }

    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("error: {problem}");
        }
        bail!("release-check: {} problem(s)", problems.len());
    }
    if let Some(path) = &args.github_output {
        write_github_output(path, &tag)?;
    }
    println!(
        "release-check: {} ok (version {}, pre-release {})",
        args.tag,
        tag.version,
        tag.is_prerelease()
    );
    Ok(())
}

/// Every manifest whose version differs from the tag's.
fn version_problems(tag: &ReleaseTag, manifests: &[(&str, String)]) -> Vec<String> {
    manifests
        .iter()
        .filter(|(_, version)| *version != tag.version)
        .map(|(file, version)| format!("{file} has version {version}, the tag has {}", tag.version))
        .collect()
}

/// A missing, empty or differently dated changelog section.
fn changelog_problem(tag: &ReleaseTag, changelog: &str) -> Option<String> {
    match changelog_section(changelog, &tag.version) {
        Ok(section) if section.date == tag.date => None,
        Ok(section) => Some(format!(
            "CHANGELOG.md dates {} as {}, the tag says {}",
            tag.version, section.date, tag.date
        )),
        Err(error) => Some(format!("{error:#}")),
    }
}

fn json_version(path: &Path) -> anyhow::Result<String> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("{} has no string `version`", path.display()))
}

fn is_ancestor(root: &Path, commit: &str, main_ref: &str) -> anyhow::Result<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["merge-base", "--is-ancestor", commit, main_ref])
        .status()
        .context("running git")?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!(
            "git merge-base --is-ancestor {commit} {main_ref} failed ({status}); is {main_ref} fetched?"
        ),
    }
}

fn write_github_output(path: &Path, tag: &ReleaseTag) -> anyhow::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(file, "version={}", tag.version)?;
    writeln!(file, "prerelease={}", tag.is_prerelease())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag() -> ReleaseTag {
        ReleaseTag::parse("v2026.09.06-0.1.0").unwrap()
    }

    #[test]
    fn matching_manifests_have_no_problems() {
        let manifests = [("a", "0.1.0".to_owned()), ("b", "0.1.0".to_owned())];
        assert!(version_problems(&tag(), &manifests).is_empty());
    }

    #[test]
    fn a_manifest_with_another_version_is_named() {
        let manifests = [
            ("a", "0.1.0".to_owned()),
            ("apps/desktop/package.json", "0.2.0".to_owned()),
        ];
        assert_eq!(
            version_problems(&tag(), &manifests),
            ["apps/desktop/package.json has version 0.2.0, the tag has 0.1.0"]
        );
    }

    #[test]
    fn changelog_date_must_match_the_tag() {
        assert_eq!(
            changelog_problem(&tag(), "## [0.1.0] - 2026-09-06\n- x\n"),
            None
        );
        assert_eq!(
            changelog_problem(&tag(), "## [0.1.0] - 2026-09-07\n- x\n").unwrap(),
            "CHANGELOG.md dates 0.1.0 as 2026-09-07, the tag says 2026-09-06"
        );
        let missing = changelog_problem(&tag(), "## [Unreleased]\n- x\n").unwrap();
        assert!(missing.contains("no `## [0.1.0]"), "{missing}");
    }

    #[test]
    fn workspace_version_is_the_manifest_version() {
        let cargo =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml")).unwrap();
        assert!(cargo.contains(&format!("version = \"{WORKSPACE_VERSION}\"")));
    }
}
