// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { describe, expect, it } from "vitest";
import { groupEvidence } from "./grouping";
import type { Evidence } from "./types";

const row = (rule_id: string, collector: string, state: Evidence["state"]): Evidence =>
  state === "found"
    ? { rule_id, collector, strength: "posture", state, observations: [] }
    : state === "not_found"
      ? { rule_id, collector, strength: "posture", state, retention: "now" }
      : { rule_id, collector, strength: "posture", state, reason: "source_absent", expected: true };

// The core's order (`rongroi_core::view::COLLECTOR_ORDER`), as a view carries it.
const ORDER = [
  "posture",
  "driver_service",
  "fivem_dir",
  "net_config",
  "process",
  "evtx",
  "prefetch",
  "bam",
  "pca",
  "usn",
];

describe("groupEvidence", () => {
  const evidence = [
    row("e1", "evtx", "not_found"),
    row("p1", "posture", "not_found"),
    row("f1", "fivem_dir", "unmeasured"),
    row("p2", "posture", "found"),
    row("x1", "future_collector", "found"),
    row("p3", "posture", "unmeasured"),
    row("p4", "posture", "not_found"),
  ];

  it("groups by collector in the fixed order, unknown collectors last", () => {
    expect(groupEvidence(evidence, null, ORDER).map((g) => g.collector)).toEqual([
      "posture",
      "fivem_dir",
      "evtx",
      "future_collector",
    ]);
  });

  it("puts found first, then unmeasured, then not found, keeping the view's order inside a state", () => {
    const posture = groupEvidence(evidence, null, ORDER)[0];
    expect(posture?.rows.map((r) => r.rule_id)).toEqual(["p2", "p3", "p1", "p4"]);
  });

  it("keeps only one state when filtered, and drops groups left empty", () => {
    const groups = groupEvidence(evidence, "found", ORDER);
    expect(groups.map((g) => [g.collector, g.rows.map((r) => r.rule_id)])).toEqual([
      ["posture", ["p2"]],
      ["future_collector", ["x1"]],
    ]);
  });
});
