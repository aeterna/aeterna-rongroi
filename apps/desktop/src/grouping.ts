// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// How the report's rows are grouped and ordered. Presentation only: which evidence is listed is
// decided in `rongroi-core::view` (ADR 0045).

import type { Evidence } from "./types";

/** The order collector groups appear in. A collector not named here follows, in first-seen order. */
export const COLLECTOR_ORDER = [
  "posture",
  "fivem_dir",
  "process",
  "evtx",
  "prefetch",
  "bam",
  "pca",
  "usn",
] as const;

export type StateFilter = Evidence["state"];

export interface EvidenceGroup {
  collector: string;
  /** Found, then unmeasured, then not found; inside a state, in the order the view listed them. */
  rows: Evidence[];
}

const RANK: Record<StateFilter, number> = { found: 0, unmeasured: 1, not_found: 2 };

export function groupEvidence(evidence: Evidence[], filter: StateFilter | null): EvidenceGroup[] {
  const kept = filter ? evidence.filter((item) => item.state === filter) : evidence;
  const collectors: string[] = [...COLLECTOR_ORDER];
  for (const item of kept) {
    if (!collectors.includes(item.collector)) {
      collectors.push(item.collector);
    }
  }
  return collectors.flatMap((collector) => {
    // `Array.prototype.sort` is stable, so rows of one state keep the view's order.
    const rows = kept
      .filter((item) => item.collector === collector)
      .sort((a, b) => RANK[a.state] - RANK[b.state]);
    return rows.length === 0 ? [] : [{ collector, rows }];
  });
}
