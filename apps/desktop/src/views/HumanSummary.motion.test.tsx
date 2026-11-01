// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { initI18n } from "../i18n";
import type { ReportView } from "../types";
import { HumanSummary } from "./HumanSummary";
import { Odometer } from "./HumanSummary.odometer";

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/rongroi-collectors/tests/snapshots");

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

const originalMatchMedia = window.matchMedia;

function stubReducedMotion() {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn((query: string) => ({
      matches: true,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
}

beforeAll(async () => {
  await initI18n("en");
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: originalMatchMedia,
  });
});

describe("HumanSummary motion", () => {
  it("keeps each tally count in the DOM as real text from the first render", () => {
    const view = snapshot("secure_boot_off_self_view");
    const { container } = render(
      <HumanSummary view={view} header={view.header} texts={{}} onSwitchToTechnical={vi.fn()} />,
    );
    const numbers = Array.from(container.querySelectorAll(".tally-item .odometer-value")).map(
      (node) => node.textContent,
    );
    expect(numbers).toEqual([
      String(view.listed.found),
      String(view.listed.not_found),
      String(view.listed.unmeasured),
    ]);
    for (const strips of container.querySelectorAll(".tally-item .odometer-strips")) {
      expect(strips.getAttribute("aria-hidden")).toBe("true");
    }
  });

  it("shows every digit at its final place at once under reduced motion", () => {
    stubReducedMotion();
    const frame = vi.spyOn(window, "requestAnimationFrame");
    const { container } = render(<Odometer value={23} />);
    const strips = Array.from(container.querySelectorAll<HTMLElement>(".odometer-strip"));
    expect(strips.map((strip) => strip.style.transform)).toEqual([
      "translateY(-2em)",
      "translateY(-3em)",
    ]);
    expect(frame).not.toHaveBeenCalled();
  });

  it("cancels the pending start frame when it unmounts", () => {
    const frame = vi.spyOn(window, "requestAnimationFrame").mockReturnValue(7);
    const cancel = vi.spyOn(window, "cancelAnimationFrame").mockImplementation(() => {});
    const { unmount } = render(<Odometer value={5} />);
    unmount();
    expect(frame).toHaveBeenCalledTimes(1);
    expect(cancel).toHaveBeenCalledWith(7);
  });
});
