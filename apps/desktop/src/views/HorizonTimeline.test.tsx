// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// ADR 0084 decision 1: the first step's number is the days since Windows was installed or, when that
// is not known, since the last boot. Its words say which anchor gave the number.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import i18n, { initI18n } from "../i18n";
import type { AnchorAge, ReportView } from "../types";
import { HorizonTimeline } from "./HorizonTimeline";

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/rongroi-collectors/tests/snapshots");

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

const BASE = snapshot("secure_boot_off_self_view");

/** A view whose trace ages carry these anchors, with no evidence and no unmeasured checks. */
function viewWithAnchors(anchors: AnchorAge[]): ReportView {
  return {
    ...BASE,
    evidence: [],
    listed: { found: 0, not_found: 0, unmeasured: 0 },
    trace_ages: { anchors, rows: [] },
  };
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

describe("HorizonTimeline first step", () => {
  it("says Windows installed when the install date is known", () => {
    const view = viewWithAnchors([
      { anchor: "install_date", state: "measured", on: "2025-10-21", days_before: 72 },
      { anchor: "boot_time", state: "measured", on: "2025-12-28", days_before: 3 },
    ]);
    const { container } = render(<HorizonTimeline view={view} header={view.header} />);
    // The first step is the history origin; its sub-label names the anchor its number came from.
    const firstSub = container.querySelector(".timeline-step .timeline-sub");
    expect(firstSub?.textContent).toBe("Windows installed");
    expect(screen.queryByText("Event Logs recorded continuously")).toBeNull();
  });

  it("says Last boot when only the boot time is known", () => {
    const view = viewWithAnchors([
      { anchor: "install_date", state: "unmeasured", reason: "source_absent" },
      { anchor: "boot_time", state: "measured", on: "2025-12-28", days_before: 3 },
    ]);
    const { container } = render(<HorizonTimeline view={view} header={view.header} />);
    const firstSub = container.querySelector(".timeline-step .timeline-sub");
    expect(firstSub?.textContent).toBe("Last boot");
    expect(screen.queryByText("Event Logs recorded continuously")).toBeNull();
  });
});

describe("HorizonTimeline badge, with no tamper evidence", () => {
  it("says no log clearing was found in what was read", () => {
    const view = viewWithAnchors([
      { anchor: "install_date", state: "measured", on: "2025-10-21", days_before: 72 },
    ]);
    const { container } = render(<HorizonTimeline view={view} header={view.header} />);
    expect(container.querySelector(".timeline-badge")?.textContent).toBe(
      "No log clearing found in what was read",
    );
    expect(screen.queryByText("Continuous History · No Wiping Detected")).toBeNull();
  });
});
