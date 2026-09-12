// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask check-unicode`: no invisible or bidi control characters in any text file.
//! Prevents "Trojan Source" (CVE-2021-42574) and hidden text that reviewers cannot see.

use std::path::Path;

use anyhow::bail;

// `corpus` and `artifacts` hold inputs libFuzzer invented (fuzz/, ADR 0016). They are generated, not
// committed, and a run that happens to produce a byte order mark must not fail this check.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "dist",
    "gen",
    "corpus",
    "artifacts",
];
const MAX_BYTES: u64 = 5 * 1024 * 1024;

fn is_forbidden(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'   // zero-width space/joiners, LRM, RLM
        | '\u{202A}'..='\u{202E}' // bidi embeddings and overrides
        | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
        | '\u{2066}'..='\u{2069}' // bidi isolates
        | '\u{FEFF}'              // byte-order mark / zero-width no-break space
    )
}

pub fn run(root: &Path) -> anyhow::Result<()> {
    let mut findings = Vec::new();
    let mut scanned = 0;
    walk(root, root, &mut findings, &mut scanned)?;
    if findings.is_empty() {
        println!("check-unicode: {scanned} text file(s) ok");
        Ok(())
    } else {
        for finding in &findings {
            eprintln!("error: {finding}");
        }
        bail!("check-unicode: {} forbidden character(s)", findings.len())
    }
}

fn walk(
    root: &Path,
    dir: &Path,
    findings: &mut Vec<String>,
    scanned: &mut usize,
) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if !SKIP_DIRS.iter().any(|skip| name == *skip) {
                walk(root, &path, findings, scanned)?;
            }
            continue;
        }
        if entry.metadata()?.len() > MAX_BYTES {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue; // binary
        };
        if text.contains('\0') {
            continue;
        }
        *scanned += 1;
        for (line_number, line) in text.lines().enumerate() {
            for (column, c) in line.chars().enumerate() {
                if is_forbidden(c) {
                    findings.push(format!(
                        "{}:{}:{}: U+{:04X}",
                        crate::display(root, &path),
                        line_number + 1,
                        column + 1,
                        u32::from(c)
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_forbidden;

    #[test]
    fn thai_text_is_allowed_and_invisible_characters_are_not() {
        assert!(
            "ร่องรอย Secure Boot ถูกปิดอยู่"
                .chars()
                .all(|c| !is_forbidden(c))
        );
        for c in ['\u{200B}', '\u{202E}', '\u{2066}', '\u{FEFF}'] {
            assert!(is_forbidden(c), "U+{:04X}", u32::from(c));
        }
    }
}
