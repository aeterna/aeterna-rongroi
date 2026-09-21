// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// This file is shared by `build.rs` (via `include!`) and by the `source-tree` feature, so the
// embedded bundle and `cargo xtask check-rules` read the rules tree in exactly the same way.
// It uses fully qualified paths because it is included into two different crates.

/// Collects every `rule.yaml` (outside `deprecated/`), the `*.csv` files beside each one, and every
/// `i18n/<lang>.yaml` under `rules_dir` into the raw bundle JSON. Paths are sorted and line endings
/// normalised, so the bundle and its SHA-256 are identical on every platform.
pub fn collect_bundle_json(rules_dir: &std::path::Path) -> std::io::Result<String> {
    let mut rules: Vec<(String, String, std::collections::BTreeMap<String, String>)> = Vec::new();
    if rules_dir.is_dir() {
        collect_rule_files(rules_dir, rules_dir, &mut rules)?;
    }
    rules.sort_by(|a, b| a.0.cmp(&b.0));

    let mut i18n: Vec<(String, String)> = Vec::new();
    let i18n_dir = rules_dir.join("i18n");
    if i18n_dir.is_dir() {
        for entry in std::fs::read_dir(&i18n_dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "yaml")
                && let Some(lang) = path.file_stem().and_then(|stem| stem.to_str())
            {
                i18n.push((lang.to_owned(), read_normalised(&path)?));
            }
        }
    }
    i18n.sort_by(|a, b| a.0.cmp(&b.0));

    let json = serde_json::json!({
        "rules": rules
            .iter()
            .map(|(path, yaml, data)| {
                if data.is_empty() {
                    serde_json::json!({ "path": path, "yaml": yaml })
                } else {
                    serde_json::json!({ "path": path, "yaml": yaml, "data": data })
                }
            })
            .collect::<Vec<_>>(),
        "i18n": i18n
            .iter()
            .map(|(lang, yaml)| serde_json::json!({ "lang": lang, "yaml": yaml }))
            .collect::<Vec<_>>(),
    });
    Ok(json.to_string())
}

fn collect_rule_files(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<(String, String, std::collections::BTreeMap<String, String>)>,
) -> std::io::Result<()> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name == "deprecated" || name == "i18n" || name == "tests" {
                continue;
            }
            collect_rule_files(root, &path, out)?;
        } else if name == "rule.yaml" {
            let relative = path.strip_prefix(root).map_err(std::io::Error::other)?;
            let relative = relative
                .components()
                .map(|component| component.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((relative, read_normalised(&path)?, data_beside(dir)?));
        }
    }
    Ok(())
}

/// Every `*.csv` directly inside `dir`, by file name, line endings normalised (ADR 0048). A rule names
/// the ones it reads in `match_lists`; `rules::expand_match_lists` refuses a name that is not here.
fn data_beside(
    dir: &std::path::Path,
) -> std::io::Result<std::collections::BTreeMap<String, String>> {
    let mut data = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file()
            && path.extension().is_some_and(|ext| ext == "csv")
            && let Some(name) = path.file_name().and_then(|name| name.to_str())
        {
            data.insert(name.to_owned(), read_normalised(&path)?);
        }
    }
    Ok(data)
}

fn read_normalised(path: &std::path::Path) -> std::io::Result<String> {
    Ok(std::fs::read_to_string(path)?.replace("\r\n", "\n"))
}
