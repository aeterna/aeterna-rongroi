// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask new-rule <collector> <category>/<slug>`: one folder with everything a rule PR needs.
//! The generated fixtures are placeholders and fail `check-rules` until they are filled in.

use std::path::Path;

use anyhow::{Context, bail};

pub fn run(root: &Path, collector: &str, path: &str) -> anyhow::Result<()> {
    let Some((category, slug)) = path.split_once('/') else {
        bail!("expected `<category>/<slug>`, got `{path}`");
    };
    let kebab = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let snake = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    if !snake(collector) {
        bail!("collector `{collector}` must be snake_case");
    }
    if !kebab(category) || !kebab(slug) {
        bail!("category and slug must be kebab-case, got `{category}/{slug}`");
    }

    let dir = root.join("rules").join(collector).join(category).join(slug);
    if dir.exists() {
        bail!("{} already exists", crate::display(root, &dir));
    }
    std::fs::create_dir_all(dir.join("tests/positive"))?;
    std::fs::create_dir_all(dir.join("tests/negative"))?;

    let id = uuid::Uuid::new_v4();
    let today = jiff::Timestamp::now().strftime("%Y-%m-%d").to_string();
    let rule = format!(
        "# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: CC-BY-SA-4.0
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.
id: {id}
title: TODO short English title
description: >-
  TODO what this evidence means, why it matters, and what it does not prove.
status: experimental
collector: {collector}
strength: TODO  # execution | presence | tamper | posture | context
match:
  TODO_field: TODO_value
retention: TODO how far back this source can see.
unmeasured_when: []  # reasons this collector can report and you expect here; check-rules rejects the rest
falsepositives:
  - TODO what legitimately produces this evidence
references: []
author: TODO your name or handle
date: {today}
tags: []
"
    );
    std::fs::write(dir.join("rule.yaml"), rule).context("writing rule.yaml")?;

    let fixture = |description: &str| {
        format!(
            "{{\n  \"description\": \"{description}\",\n  \"observations\": [\n    {{ \"collector\": \"{collector}\", \"fields\": {{ \"TODO_field\": \"TODO\" }} }}\n  ]\n}}\n"
        )
    };
    std::fs::write(
        dir.join("tests/positive/example.json"),
        fixture("TODO observations that must make this rule match"),
    )?;
    std::fs::write(
        dir.join("tests/negative/example.json"),
        fixture("TODO observations from a legitimate machine that must not match"),
    )?;

    println!("created {}", crate::display(root, &dir));
    println!("next: fill in rule.yaml and both fixtures, then run `cargo xtask check-rules`");
    Ok(())
}
