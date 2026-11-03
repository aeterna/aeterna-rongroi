// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// H10: the timeline's entrance is decoration. The steps keep their real labels and tags in the DOM
// from the first render, carry their place in the stagger as `--i`, and the motion is confined to
// the no-preference guard so reduced motion shows the finished timeline.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import i18n, { initI18n } from "../i18n";
import type { AnchorAge, ReportView } from "../types";
import { HorizonTimeline } from "./HorizonTimeline";

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/rongroi-collectors/tests/snapshots");
const MOTION_CSS = readFileSync(
  resolve(process.cwd(), "src/views/HorizonTimeline.motion.css"),
  "utf8",
);

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

const BASE = snapshot("secure_boot_off_self_view");

/** A view with these trace anchors, no evidence, no cross-source and no unmeasured checks. */
function viewWithAnchors(anchors: AnchorAge[]): ReportView {
  return {
    ...BASE,
    evidence: [],
    listed: { found: 0, not_found: 0, unmeasured: 0 },
    trace_ages: { anchors, rows: [] },
  };
}

/** The four steps of a timeline whose history origin is 72 days before the scan. */
function measuredView(): ReportView {
  return viewWithAnchors([
    { anchor: "install_date", state: "measured", on: "2025-10-21", days_before: 72 },
    { anchor: "boot_time", state: "measured", on: "2025-12-28", days_before: 3 },
  ]);
}

/** The body of each `@keyframes` block, found with brace matching so nested rules stay intact. */
function keyframeBlocks(css: string): string[] {
  const blocks: string[] = [];
  for (const match of css.matchAll(/@keyframes\s+[\w-]+\s*\{/g)) {
    const open = (match.index ?? 0) + (match[0] ?? "").length - 1;
    let depth = 0;
    for (let index = open; index < css.length; index += 1) {
      if (css[index] === "{") depth += 1;
      else if (css[index] === "}") {
        depth -= 1;
        if (depth === 0) {
          blocks.push(css.slice(open, index + 1));
          break;
        }
      }
    }
  }
  return blocks;
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

describe("HorizonTimeline entrance stagger", () => {
  it("marks the track and numbers the steps 0..n-1 in document order", () => {
    const view = measuredView();
    const { container } = render(<HorizonTimeline view={view} header={view.header} />);

    const track = container.querySelector(".timeline-track");
    expect(track?.classList.contains("timeline-enter")).toBe(true);

    const steps = Array.from(container.querySelectorAll<HTMLElement>(".timeline-step"));
    expect(steps).toHaveLength(4);
    expect(steps.map((step) => step.style.getPropertyValue("--i"))).toEqual([
      "0",
      "1",
      "2",
      "3",
    ]);
    // The entrance only appends its marker; the classes existing CSS and tests rely on stay.
    expect(steps.map((step) => step.classList.contains("timeline-step"))).toEqual([
      true,
      true,
      true,
      true,
    ]);
  });

  it("keeps every label and tag rendering as before", () => {
    const view = measuredView();
    const { container } = render(<HorizonTimeline view={view} header={view.header} />);

    const labels = Array.from(container.querySelectorAll(".timeline-label")).map(
      (node) => node.textContent,
    );
    expect(labels).toEqual(["History Origin", "Last Boot", "Last FiveM Play", "Current Scan"]);

    const tags = Array.from(container.querySelectorAll(".timeline-tag")).map(
      (node) => node.textContent,
    );
    expect(tags).toEqual(["72d", "3d 2h", "-", "This scan"]);

    const subs = Array.from(container.querySelectorAll(".timeline-step .timeline-sub")).map(
      (node) => node.textContent,
    );
    expect(subs).toEqual([
      "Windows installed",
      "2025-12-28 21:56",
      "No recent FiveM sessions recorded in the inspected horizon",
      "2026-01-01 00:00",
    ]);
  });
});

describe("HorizonTimeline motion CSS", () => {
  it("keeps the whole entrance inside the no-preference guard", () => {
    expect(MOTION_CSS).toContain("@media (prefers-reduced-motion: no-preference)");
    const guard = MOTION_CSS.indexOf("@media (prefers-reduced-motion: no-preference)");
    expect(guard).toBeGreaterThan(-1);
    for (const marker of [
      ".timeline-enter .timeline-line",
      ".timeline-enter .timeline-step",
      "@keyframes timeline-line-grow",
      "@keyframes timeline-step-in",
    ]) {
      expect(MOTION_CSS.indexOf(marker)).toBeGreaterThan(guard);
    }
  });

  it("plays once: no iteration count other than 1 and no repeat keyword", () => {
    const counts = Array.from(
      MOTION_CSS.matchAll(/animation-iteration-count\s*:\s*([^;]+);/g),
      (match) => (match[1] ?? "").trim(),
    );
    for (const count of counts) {
      expect(count).toBe("1");
    }
    expect(MOTION_CSS).not.toMatch(/\binfinite\b/);
  });

  it("leaves every opacity animation at its final value of 1", () => {
    const blocks = keyframeBlocks(MOTION_CSS);
    expect(blocks.length).toBeGreaterThan(0);
    for (const block of blocks) {
      const opacities = Array.from(block.matchAll(/opacity\s*:\s*([\d.]+)/g), (match) =>
        Number(match[1]),
      );
      if (opacities.length > 0) {
        expect(opacities.at(-1)).toBe(1);
      }
    }
    // The step fade in particular carries the ordinary resting opacity at its end.
    const stepIn = blocks.find((block) => block.includes("translateY(6px)"));
    expect(stepIn).toBeDefined();
    expect(stepIn).toMatch(/opacity\s*:\s*1\s*;/);
  });
});
