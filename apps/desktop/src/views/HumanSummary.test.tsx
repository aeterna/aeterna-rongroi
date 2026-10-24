// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// ADR 0084 decision 1: the overview states counts, not a verdict. Each sentence below is from the
// ADR's text table, exactly.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import i18n, { initI18n } from "../i18n";
import enReport from "../locales/en/report.json";
import thReport from "../locales/th/report.json";
import type { Evidence, ReportView } from "../types";
import { HumanSummary } from "./HumanSummary";

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/rongroi-collectors/tests/snapshots");

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

const BASE = snapshot("secure_boot_off_self_view");
const TAMPER_RULE_ID = "3b9e1c2a-5d7f-4e8a-9c1b-2f6d8a0e4b71";
const POSTURE_RULE_ID = "7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7";
const UNMEASURED_RULE_ID = "0a6d4e8f-2b1c-4f7a-8e3d-9c5b7a1f2e6d";

const EN_EVIDENCE_ONLY = "Evidence only. This report cannot prove that a PC is clean.";
const TH_EVIDENCE_ONLY = "เป็นหลักฐานประกอบเท่านั้น รายงานนี้พิสูจน์ไม่ได้ว่าเครื่องสะอาด";
const EN_TAMPER_HERO =
  "1 found of strength tamper: traces that something changed what Windows records or what a scan reads. What came before may not be visible. Each one is listed below.";

/** A view with exactly these evidence rows, and the counts that go with them. */
function viewWith(evidence: Evidence[]): ReportView {
  const count = (state: Evidence["state"]) => evidence.filter((e) => e.state === state).length;
  return {
    ...BASE,
    evidence,
    listed: {
      found: count("found"),
      not_found: count("not_found"),
      unmeasured: count("unmeasured"),
    },
    cross_source: [],
  };
}

const POSTURE_FOUND: Evidence = {
  rule_id: POSTURE_RULE_ID,
  collector: "posture",
  strength: "posture",
  state: "found",
  observations: [{ collector: "posture", fields: { secure_boot: "off" } }],
};

const UNMEASURED_ONE: Evidence = {
  rule_id: UNMEASURED_RULE_ID,
  collector: "evtx",
  strength: "execution",
  state: "unmeasured",
  reason: "not_admin",
  expected: true,
};

const TAMPER_FOUND: Evidence = {
  rule_id: TAMPER_RULE_ID,
  collector: "evtx",
  strength: "tamper",
  state: "found",
  observations: [{ collector: "evtx", fields: { channel: "System" } }],
};

/** The overview's findings card: the glance card whose title is `title`. */
function glanceCard(title: string): HTMLElement {
  const card = screen.getByText(title).closest(".glance-card");
  if (!(card instanceof HTMLElement)) {
    throw new Error(`no glance card titled ${title}`);
  }
  return card;
}

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
});

afterEach(() => {
  cleanup();
});

describe("HumanSummary hero, with no tamper evidence and few unmeasured checks", () => {
  // The sentence is the common `footer.evidence_only`, which the rest of the report already uses.
  const FORBIDDEN_EN = [
    "benign",
    "Benign",
    "No Wiping",
    "typical",
    "Continuous",
    "Offline Sealed",
    "Tamper Detected",
    "Wiped",
  ];
  const FORBIDDEN_TH = ["ปกติของโปรแกรม", "ไม่มีการล้างประวัติ", "ต่อเนื่อง"];

  it("shows the evidence-only sentence in English and no verdict wording", () => {
    const view = viewWith([POSTURE_FOUND, UNMEASURED_ONE]);
    const { container } = render(
      <HumanSummary view={view} header={view.header} texts={{}} onSwitchToTechnical={vi.fn()} />,
    );
    expect(screen.getByText(EN_EVIDENCE_ONLY)).toBeTruthy();
    for (const word of FORBIDDEN_EN) {
      expect(container.textContent ?? "").not.toContain(word);
    }
  });

  it("shows the evidence-only sentence in Thai and no verdict wording", async () => {
    await i18n.changeLanguage("th");
    const view = viewWith([POSTURE_FOUND, UNMEASURED_ONE]);
    const { container } = render(
      <HumanSummary view={view} header={view.header} texts={{}} onSwitchToTechnical={vi.fn()} />,
    );
    expect(screen.getByText(TH_EVIDENCE_ONLY)).toBeTruthy();
    for (const word of FORBIDDEN_TH) {
      expect(container.textContent ?? "").not.toContain(word);
    }
  });

  it("shows no badge on the findings card", () => {
    const view = viewWith([POSTURE_FOUND, UNMEASURED_ONE]);
    render(
      <HumanSummary view={view} header={view.header} texts={{}} onSwitchToTechnical={vi.fn()} />,
    );
    expect(glanceCard("Findings Overview").querySelector(".glance-badge")).toBeNull();
  });
});

describe("HumanSummary hero, with one found item of strength tamper", () => {
  it("shows the tamper sentence with its count of 1", () => {
    const view = viewWith([TAMPER_FOUND]);
    render(
      <HumanSummary view={view} header={view.header} texts={{}} onSwitchToTechnical={vi.fn()} />,
    );
    const hero = document.querySelector(".hero-note .hero-desc");
    expect(hero?.textContent).toBe(EN_TAMPER_HERO);
  });

  it("shows the tamper badge on the findings card", () => {
    const view = viewWith([TAMPER_FOUND]);
    render(
      <HumanSummary view={view} header={view.header} texts={{}} onSwitchToTechnical={vi.fn()} />,
    );
    expect(glanceCard("Findings Overview").querySelector(".glance-badge")?.textContent).toBe(
      "Tamper evidence found",
    );
  });

  it("names no cleared log and no USN reset", () => {
    const view = viewWith([TAMPER_FOUND]);
    const { container } = render(
      <HumanSummary view={view} header={view.header} texts={{}} onSwitchToTechnical={vi.fn()} />,
    );
    expect(container.textContent ?? "").not.toMatch(/Event Log cleared/);
    expect(container.textContent ?? "").not.toMatch(/USN Reset/);
  });
});

// ADR 0084 decision 1 removes these keys; no locale may still carry them.
describe("locales after ADR 0084 decision 1", () => {
  const REMOVED_KEYS = [
    "hero_note.reassurance_benign",
    "hero_note.reassurance_proxy",
    "glance.history_clean_badge",
    "glance.history_clean_desc",
    "glance.obs_benign_badge",
    "glance.obs_benign_desc",
    "glance.fivem_session_text",
    "horizon_timeline.badge_continuous",
    "horizon_timeline.badge_short",
    "horizon_timeline.step_history_start_sub",
  ];

  function hasKey(tree: unknown, path: string): boolean {
    let node: unknown = tree;
    for (const part of path.split(".")) {
      if (typeof node !== "object" || node === null || !(part in node)) {
        return false;
      }
      node = (node as Record<string, unknown>)[part];
    }
    return true;
  }

  it("keeps none of the removed keys in en or th report.json", () => {
    const stillThere = REMOVED_KEYS.flatMap((key) => {
      const hits: string[] = [];
      if (hasKey(enReport, key)) hits.push(`en: ${key}`);
      if (hasKey(thReport, key)) hits.push(`th: ${key}`);
      return hits;
    });
    expect(stillThere).toEqual([]);
  });
});
