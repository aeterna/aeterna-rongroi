// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// The only way the UI talks to Rust: local Tauri IPC commands. No network (ADR 0003).

import { invoke } from "@tauri-apps/api/core";
import type { Mode, ReportHeader, ReportView, RuleText } from "./types";

/** Facts about the scan (provenance, platform) without any evidence. */
export function reportHeader(): Promise<ReportHeader> {
  return invoke<ReportHeader>("report_header");
}

/** The frozen report as `mode` may see it. Filtering and redaction happen in Rust. */
export function reportView(mode: Mode): Promise<ReportView> {
  return invoke<ReportView>("report_view", { mode });
}

/** Rule text in `lang`, keyed by rule id, English fallback applied in Rust. */
export function ruleTexts(lang: string): Promise<Record<string, RuleText>> {
  return invoke<Record<string, RuleText>>("rule_texts", { lang });
}
