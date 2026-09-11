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
  | "access_denied"
  | "service_disabled"
  | "source_missing"
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
  | { state: "unmeasured"; reason: UnmeasuredReason };

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

export interface ReportHeader {
  schema_version: number;
  provenance: Provenance;
  rules_bundle: { schema_version: number; sha256: string; rule_count: number };
  platform: string;
  os_build: string | null;
  elevated: boolean | null;
  generated_at: string;
}

export interface ReportView {
  mode: Mode;
  header: ReportHeader;
  evidence: Evidence[];
  hidden: { not_found: number; unmeasured: number };
}

export interface RuleText {
  title: string;
  description: string;
  falsepositives: string[];
  /** Look-back note for `not_found`, translated. Evidence keeps the English source. */
  retention: string;
}
