// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask new-locale <bcp47>`: copies the English UI strings and creates a rule translation file.

use std::path::Path;

use anyhow::bail;
use rongroi_core::rules::is_lang;

pub fn run(root: &Path, lang: &str) -> anyhow::Result<()> {
    if !is_lang(lang) {
        bail!("`{lang}` is not a BCP 47 tag such as `th`, `vi` or `pt-BR`");
    }
    if lang == "en" {
        bail!("English is the source language; edit the files in place");
    }

    let english = root.join("apps/desktop/src/locales/en");
    let target = root.join("apps/desktop/src/locales").join(lang);
    if english.is_dir() {
        if target.exists() {
            bail!("{} already exists", crate::display(root, &target));
        }
        std::fs::create_dir_all(&target)?;
        for entry in std::fs::read_dir(&english)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "json")
                && let Some(name) = path.file_name()
            {
                std::fs::copy(&path, target.join(name))?;
            }
        }
        println!(
            "created {} (English copies — translate the values)",
            crate::display(root, &target)
        );
    }

    let rules_file = root.join("rules/i18n").join(format!("{lang}.yaml"));
    if rules_file.exists() {
        println!("{} already exists", crate::display(root, &rules_file));
    } else {
        std::fs::write(
            &rules_file,
            format!(
                "# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: CC-BY-SA-4.0
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.
# Rule text in `{lang}`, keyed by rule id. Anything omitted falls back to English. See rules/i18n/th.yaml.
# Translatable fields: title, description, falsepositives, retention.
"
            ),
        )?;
        println!("created {}", crate::display(root, &rules_file));
    }
    println!(
        "next: register `{lang}` in apps/desktop/src/i18n.ts, then run `cargo xtask check-locales`"
    );
    Ok(())
}
