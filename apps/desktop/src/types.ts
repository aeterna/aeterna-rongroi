// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// Mirrors crates/rongroi-core/src/model.rs and view.rs. The UI tests feed these types with the Rust
// report snapshots, so a drift between the two fails `pnpm test`. (Generating them with ts-rs is planned.)

export type Mode = "self" | "ss";

export type UnmeasuredReason =
  | "not_windows"
  | "not_on_this_os"
  | "not_admin"
  | "not_attempted"
  | "access_denied"
  | "service_disabled"
  | "source_absent"
  | "source_empty"
  | "partial"
  | "budget_spent"
  | "read_failed"
  | "collector_unavailable";

export type Strength = "execution" | "presence" | "tamper" | "posture" | "context";

export interface Observation {
  collector: string;
  fields: Record<string, unknown>;
}

export type EvidenceState =
  | { state: "found"; observations: Observation[] }
  | { state: "not_found"; retention: string }
  /** `expected` is whether the rule named this reason in its `unmeasured_when` (ADR 0027). */
  | { state: "unmeasured"; reason: UnmeasuredReason; expected: boolean };

export type Evidence = {
  rule_id: string;
  collector: string;
  strength: Strength;
} & EvidenceState;

export interface Provenance {
  official: boolean;
  version: string;
  commit: string | null;
  exe_sha256: string | null;
}

/**
 * When the running Windows kernel started counting (ADR 0039). Context for reading the times on the
 * rows, never evidence. A "Shut down" with Fast Startup, sleep and hibernation do not reset it.
 */
export type BootTime =
  | { state: "measured"; booted_at: string; seconds_since_boot: number }
  | { state: "unmeasured"; reason: UnmeasuredReason };

export interface ReportHeader {
  schema_version: number;
  provenance: Provenance;
  rules_bundle: { schema_version: number; sha256: string; rule_count: number };
  platform: string;
  os_build: string | null;
  elevated: boolean | null;
  generated_at: string;
  boot_time: BootTime;
}

/**
 * One observation that describes aeterna-rongroi itself rather than the machine. The tool is running
 * while it scans, so a collector that enumerates the machine sees it (ADR 0010).
 */
export interface OwnTraceEntry {
  collector: string;
  observation: Observation;
}

/**
 * Observations of one collector that no rule matched. A collector reads the machine whether or not a
 * rule asks about what it finds, and evidence carries observations only where a rule matched, so
 * without this bucket what such a collector saw would be read and then discarded (ADR 0014).
 */
export interface UnmatchedGroup {
  collector: string;
  observations: Observation[];
}

/** How many of the evidence a view lists are in each state (ADR 0045). Never added into one number. */
export interface ListedCounts {
  found: number;
  not_found: number;
  unmeasured: number;
}

export interface ReportView {
  mode: Mode;
  header: ReportHeader;
  evidence: Evidence[];
  /** Shown in both modes: hiding "this was us" from an SS viewer would tell them less, not more. */
  own_traces: OwnTraceEntry[];
  /** Self mode lists these; SS mode leaves the list empty and counts them in `hidden.unmatched`. */
  unmatched: UnmatchedGroup[];
  /**
   * Facts about the scan, above the evidence in both modes. `not_admin` is how many checks missing
   * administrator rights left unanswered — one fact about the scan rather than one per rule, and the
   * one with a remedy. It is not a fourth hidden count; the same checks are in `hidden` (ADR 0027).
   */
  scope: { not_admin: number; not_attempted: number };
  listed: ListedCounts;
  hidden: {
    not_found: number;
    unmeasured_expected: number;
    unmeasured_unexpected: number;
    unmatched: number;
  };
}

/** Where a rule, its fixtures and its collector are in the repository, from its root (ADR 0045). */
export interface RuleFiles {
  rule: string;
  fixtures: string;
  collector: string;
  references: string[];
}

export interface RuleText {
  title: string;
  description: string;
  falsepositives: string[];
  /** Look-back note for `not_found`, translated. Evidence keeps the English source. */
  retention: string;
  status: "experimental" | "test" | "stable" | "deprecated";
  files: RuleFiles;
}
