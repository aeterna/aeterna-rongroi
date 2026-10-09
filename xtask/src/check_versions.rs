// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask check-versions`: every place a release writes the version by hand names the workspace version.
//!
//! The landing page is filled from the published release (`cargo xtask site`); the Markdown pages cannot be,
//! because GitHub shows them as written. So a release pull request that missed one of them fails here instead
//! of shipping a guide that names the previous release.

use std::path::Path;

use anyhow::{Context, bail};

use crate::release_check::json_version;

/// The workspace version: xtask declares `version.workspace = true`.
const WORKSPACE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Text each page must contain, with `{v}` standing for the version.
const MARKERS: [(&str, &str); 4] = [
    (
        "README.md",
        "**Latest release: [{v}](https://github.com/aeterna/aeterna-rongroi/releases/tag/v",
    ),
    (
        "README.th.md",
        "**รุ่นล่าสุด: [{v}](https://github.com/aeterna/aeterna-rongroi/releases/tag/v",
    ),
    ("docs/screenshare-guide.md", "aeterna-rongroi **{v}**."),
    ("docs/screenshare-guide.th.md", "**{v}** · Read in English"),
];

/// Pages whose release file names (`aeterna-rongroi[-cli]-X.Y.Z-windows-x64.exe`) must name the version.
const FILE_NAME_PAGES: [&str; 4] = [
    "README.md",
    "README.th.md",
    "docs/screenshare-guide.md",
    "docs/screenshare-guide.th.md",
];

pub fn run(root: &Path) -> anyhow::Result<()> {
    let version = WORKSPACE_VERSION;
    let mut problems = Vec::new();
    for file in [
        "apps/desktop/src-tauri/tauri.conf.json",
        "apps/desktop/package.json",
    ] {
        let found = json_version(&root.join(file))?;
        if found != version {
            problems.push(format!(
                "{file} has version {found}, Cargo.toml has {version}"
            ));
        }
    }
    for (file, marker) in MARKERS {
        let text = read(root, file)?;
        let marker = marker.replace("{v}", version);
        if !text.contains(&marker) {
            problems.push(format!("{file} does not contain `{marker}`"));
        }
    }
    for file in FILE_NAME_PAGES {
        let text = read(root, file)?;
        for (line, named) in release_file_versions(&text) {
            if named != version {
                problems.push(format!(
                    "{file}:{line} names a {named} release file, Cargo.toml has {version}"
                ));
            }
        }
    }
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("error: {problem}");
        }
        bail!("check-versions: {} problem(s)", problems.len());
    }
    println!("check-versions: {version} everywhere");
    Ok(())
}

fn read(root: &Path, file: &str) -> anyhow::Result<String> {
    std::fs::read_to_string(root.join(file)).with_context(|| format!("reading {file}"))
}

/// `(line number, version)` of every `aeterna-rongroi-X.Y.Z-windows-x64.exe` or `-cli-` name with digits for
/// a version. `X.Y.Z` and `*` written as such are not versions and are skipped.
fn release_file_versions(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(at) = rest.find("aeterna-rongroi-") {
            let after = &rest[at + "aeterna-rongroi-".len()..];
            let after = after.strip_prefix("cli-").unwrap_or(after);
            if let Some(end) = after.find("-windows-x64.exe") {
                let version = &after[..end];
                let numeric = version.split('.').count() == 3
                    && version
                        .split('.')
                        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
                if numeric {
                    found.push((index + 1, version.to_owned()));
                }
            }
            rest = &rest[at + 1..];
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_numeric_release_file_names_only() {
        let text = "run aeterna-rongroi-cli-0.8.1-windows-x64.exe\n\
                    `aeterna-rongroi-X.Y.Z-windows-x64.exe` and aeterna-rongroi-*-windows-x64.exe\n\
                    aeterna-rongroi-0.7.0-windows-x64.exe";
        assert_eq!(
            release_file_versions(text),
            vec![(1, "0.8.1".to_owned()), (3, "0.7.0".to_owned())]
        );
    }

    #[test]
    fn the_repository_agrees_with_itself() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        run(root).unwrap();
    }
}
