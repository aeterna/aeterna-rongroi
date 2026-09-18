// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// The only way the UI talks to Rust: local Tauri IPC commands. No network (ADR 0003).

import { invoke } from "@tauri-apps/api/core";
import type { CodeLinks, Mode, ReportHeader, ReportView, RuleText, SsOptions } from "./types";

/** Facts about the scan (provenance, platform) without any evidence. */
export function reportHeader(): Promise<ReportHeader> {
  return invoke<ReportHeader>("report_header");
}

/**
 * The frozen report as `mode` may see it, with what the player agreed SS mode may show beyond its
 * default. Filtering, redaction and the placeholders happen in Rust (ADR 0052).
 */
export function reportView(mode: Mode, options?: SsOptions): Promise<ReportView> {
  return invoke<ReportView>("report_view", { mode, options: options ?? null });
}

/** What came of a request to restart with administrator rights. */
export type ElevateOutcome = "started" | "declined" | "failed";

/**
 * Starts an elevated copy of this program and closes this one; the new process scans from the beginning.
 * Declining the Windows prompt is reported as `declined`, a normal outcome rather than a failure.
 */
export function relaunchElevated(): Promise<ElevateOutcome> {
  return invoke<ElevateOutcome>("relaunch_elevated");
}

/**
 * Starts a copy of this program that asks, in a Windows dialog before it reads anything, whether to
 * run a full scan, and closes this one (ADR 0052). There is no prompt to decline here.
 */
export function relaunchFull(): Promise<ElevateOutcome> {
  return invoke<ElevateOutcome>("relaunch_full");
}

/** Rule text in `lang`, keyed by rule id, English fallback applied in Rust. */
export function ruleTexts(lang: string): Promise<Record<string, RuleText>> {
  return invoke<Record<string, RuleText>>("rule_texts", { lang });
}

/** Where this binary's code can be read: the commit of an official build, the repository otherwise. */
export function codeLinks(): Promise<CodeLinks> {
  return invoke<CodeLinks>("code_links");
}

/** A QR code of a link into the repository as SVG text, drawn in Rust; `null` for any other text. */
export function codeLinkQr(url: string): Promise<string | null> {
  return invoke<string | null>("code_link_qr", { url });
}
