// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask check-locales`: every UI locale must use only keys that exist in English.
//! Missing keys are warnings (they fall back to English); extra keys and extra files are errors.
//! Rule translations (`rules/i18n/`) are checked by `check-rules`.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, bail};
use rongroi_core::rules::is_lang;

const LOCALES: &str = "apps/desktop/src/locales";

pub fn run(root: &Path) -> anyhow::Result<()> {
    let dir = root.join(LOCALES);
    if !dir.is_dir() {
        println!("check-locales: {LOCALES} does not exist yet, nothing to check");
        return Ok(());
    }
    let english_dir = dir.join("en");
    let english_files = json_file_names(&english_dir)?;
    if english_files.is_empty() {
        bail!("check-locales: {LOCALES}/en has no JSON files");
    }

    let mut errors = Vec::new();
    let mut warnings = 0;
    let mut languages = 0;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let lang = entry.file_name().to_string_lossy().into_owned();
        if !entry.path().is_dir() || lang == "en" {
            continue;
        }
        languages += 1;
        if !is_lang(&lang) {
            errors.push(format!(
                "{LOCALES}/{lang}: not a BCP 47 tag such as `th` or `pt-BR`"
            ));
        }
        let files = json_file_names(&entry.path())?;
        for file in &files {
            if !english_files.contains(file) {
                errors.push(format!("{LOCALES}/{lang}/{file}: no such file in en/"));
                continue;
            }
            let english = keys(&english_dir.join(file))?;
            let translated = keys(&entry.path().join(file))?;
            for extra in translated.difference(&english) {
                errors.push(format!(
                    "{LOCALES}/{lang}/{file}: key `{extra}` does not exist in English"
                ));
            }
            let missing = english.difference(&translated).count();
            if missing > 0 {
                warnings += missing;
                eprintln!(
                    "warning: {LOCALES}/{lang}/{file}: {missing} key(s) not translated yet (English is shown)"
                );
            }
        }
        for file in english_files.difference(&files) {
            eprintln!(
                "warning: {LOCALES}/{lang}/{file}: file not translated yet (English is shown)"
            );
        }
    }

    if errors.is_empty() {
        println!("check-locales: en + {languages} language(s) ok, {warnings} untranslated key(s)");
        Ok(())
    } else {
        for error in &errors {
            eprintln!("error: {error}");
        }
        bail!("check-locales: {} problem(s)", errors.len())
    }
}

fn json_file_names(dir: &Path) -> anyhow::Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if Path::new(&name)
                .extension()
                .is_some_and(|ext| ext == "json")
            {
                names.insert(name);
            }
        }
    }
    Ok(names)
}

fn keys(file: &Path) -> anyhow::Result<BTreeSet<String>> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
    let mut out = BTreeSet::new();
    flatten("", &value, &mut out);
    Ok(out)
}

fn flatten(prefix: &str, value: &serde_json::Value, out: &mut BTreeSet<String>) {
    if let serde_json::Value::Object(map) = value {
        for (key, child) in map {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            flatten(&path, child, out);
        }
    } else {
        out.insert(prefix.to_owned());
    }
}
