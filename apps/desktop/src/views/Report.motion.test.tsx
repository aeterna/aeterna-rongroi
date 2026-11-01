// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// E1: the collector groups rise in once, when the technical view first opens — a fade is decoration,
// and the evidence is never waiting on a script. E2: the three tally counts roll like HumanSummary's.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import i18n, { initI18n } from "../i18n";
import type { ReportView } from "../types";
import { Report } from "./Report";

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/rongroi-collectors/tests/snapshots");

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

const VIEW = snapshot("secure_boot_off_self_view");
const GROUP_COUNT = new Set(VIEW.evidence.map((item) => item.collector)).size;

/** 120 ms per group, for the first eight groups; past them, no delay at all. */
function staggerDelayMs(index: number): string {
  return index < 8 ? `${index * 120}ms` : "0ms";
}

const originalMatchMedia = Object.getOwnPropertyDescriptor(window, "matchMedia");

/** Replaces `window.matchMedia` with one that answers the reduced-motion query as `reduced`. */
function stubReducedMotion(reduced: boolean): void {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: (query: string) =>
      ({
        matches: query === "(prefers-reduced-motion: reduce)" && reduced,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }) as unknown as MediaQueryList,
  });
}

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
  mockIPC((cmd) => {
    switch (cmd) {
      case "report_view":
        return VIEW;
      case "rule_texts":
        return {};
      case "age_texts":
        return {};
      case "code_links":
        return { repository: "https://example.invalid", code: "", commit: null };
      default:
        throw new Error(`unexpected command ${cmd}`);
    }
  });
});

afterEach(() => {
  cleanup();
  clearMocks();
  vi.restoreAllMocks();
  vi.useRealTimers();
  if (originalMatchMedia) {
    Object.defineProperty(window, "matchMedia", originalMatchMedia);
  } else {
    Reflect.deleteProperty(window, "matchMedia");
  }
});

/** Renders the report and resolves its view; both views are in the DOM, the technical one hidden. */
async function renderReport() {
  render(<Report mode="self" onBack={() => {}} />);
  await screen.findByText("Overview Summary");
}

function openTechnical() {
  fireEvent.click(screen.getByRole("button", { name: "Detailed Report" }));
}

/** A group that has finished playing (or never played) carries no animation styles of its own. */
function expectGroupsPlain() {
  expect(document.querySelector(".view-tech-wrap")?.className).toBe("view-tech-wrap");
  const groups = document.querySelectorAll<HTMLElement>(".view-tech-wrap section.group");
  expect(groups.length).toBeGreaterThan(0);
  for (const group of groups) {
    expect(group.style.animationDelay).toBe("");
    expect(group.style.opacity).toBe("");
    expect(group.style.transform).toBe("");
  }
}

describe("Report group reveal (E1)", () => {
  it("adds the reveal only when the technical view first shows, one step per group, hiding nothing", async () => {
    await renderReport();

    // Before the technical view opens the groups are already there, plain: the stagger may never
    // run, and nothing waits for a script to become visible.
    const wrap = document.querySelector(".view-tech-wrap");
    expect(wrap?.className).toBe("view-tech-wrap");
    const before = document.querySelectorAll<HTMLElement>(".view-tech-wrap section.group");
    expect(before).toHaveLength(GROUP_COUNT);
    for (const group of before) {
      expect(group.style.animationDelay).toBe("");
      expect(group.style.opacity).toBe("");
      expect(group.style.transform).toBe("");
    }

    vi.useFakeTimers();
    openTechnical();
    expect(wrap?.className).toBe("view-tech-wrap reveal-on");
    const groups = document.querySelectorAll<HTMLElement>(".view-tech-wrap section.group");
    expect(groups).toHaveLength(GROUP_COUNT);
    groups.forEach((group, index) => {
      expect(group.style.animationDelay).toBe(staggerDelayMs(index));
      expect(group.style.opacity).toBe("");
      expect(group.style.transform).toBe("");
    });
    // Every group's heading is real text in the DOM from the stagger's first frame: the fade only
    // moves the same content the reader already has.
    const headings = document.querySelectorAll(".view-tech-wrap section.group h3");
    expect(headings).toHaveLength(GROUP_COUNT);
    for (const heading of headings) {
      expect(heading.textContent).not.toBe("");
    }

    // Longer than the last staggered step plus one rise: the play is over and the class is off.
    act(() => {
      vi.advanceTimersByTime(1_340);
    });
    expectGroupsPlain();
  });

  it("plays once per mount: filtering, searching and later view toggles do not restart it", async () => {
    await renderReport();
    vi.useFakeTimers();
    openTechnical();
    // The play is on while it runs; every interaction below must never bring it back.
    expect(document.querySelector(".view-tech-wrap")?.className).toBe("view-tech-wrap reveal-on");
    act(() => {
      vi.advanceTimersByTime(1_340);
    });
    expectGroupsPlain();

    // A search that drops and re-creates groups cannot replay a play that is over.
    const search = screen.getByRole("searchbox", { name: "Search checks" });
    fireEvent.change(search, { target: { value: "posture" } });
    expectGroupsPlain();

    // Clearing the search and filtering by the found tally, twice over, keep it quiet.
    fireEvent.change(search, { target: { value: "" } });
    const found = document.querySelector(".view-tech-wrap .tally-found");
    if (!found) throw new Error("no tally-found button in the technical view");
    fireEvent.click(found);
    expectGroupsPlain();
    fireEvent.click(screen.getByRole("button", { name: "Show every state" }));
    expectGroupsPlain();

    // Switching views and back, after the play, restarts nothing.
    fireEvent.click(screen.getByRole("button", { name: "Overview Summary" }));
    expectGroupsPlain();
    openTechnical();
    expectGroupsPlain();
  });

  it("ends a play that is still running when the reader leaves, and never resumes it", async () => {
    await renderReport();
    vi.useFakeTimers();
    openTechnical();
    expect(document.querySelector(".view-tech-wrap")?.className).toBe("view-tech-wrap reveal-on");

    act(() => {
      vi.advanceTimersByTime(200);
    });
    // Leaving mid-play takes the class off at once, so a later return cannot catch a restart.
    fireEvent.click(screen.getByRole("button", { name: "Overview Summary" }));
    expectGroupsPlain();
    openTechnical();
    expectGroupsPlain();
  });

  it("shows the groups at once under reduced motion, while the ordinary path plays", async () => {
    stubReducedMotion(true);
    await renderReport();
    openTechnical();
    expectGroupsPlain();
    const headings = document.querySelectorAll(".view-tech-wrap section.group h3");
    expect(headings).toHaveLength(GROUP_COUNT);
    for (const heading of headings) {
      expect(heading.textContent).not.toBe("");
    }

    // The ordinary path, to anchor why the reduced path above is the special case.
    cleanup();
    stubReducedMotion(false);
    await renderReport();
    vi.useFakeTimers();
    openTechnical();
    expect(document.querySelector(".view-tech-wrap")?.className).toBe("view-tech-wrap reveal-on");
    act(() => {
      vi.advanceTimersByTime(1_340);
    });
    expectGroupsPlain();
  });

  it("treats a missing matchMedia as not reduced, without throwing", async () => {
    Reflect.deleteProperty(window, "matchMedia");
    await renderReport();
    vi.useFakeTimers();
    openTechnical();
    expect(document.querySelector(".view-tech-wrap")?.className).toBe("view-tech-wrap reveal-on");
    act(() => {
      vi.advanceTimersByTime(1_340);
    });
    expectGroupsPlain();
  });
});

describe("Report summary counts (E2)", () => {
  it("rolls the three tally counts on the odometer, with the real number hidden but never marked off", async () => {
    await renderReport();

    const values = Array.from(
      document.querySelectorAll(".view-tech-wrap .tally-item .odometer-value"),
    ).map((node) => node.textContent);
    expect(values).toEqual([
      String(VIEW.listed.found),
      String(VIEW.listed.not_found),
      String(VIEW.listed.unmeasured),
    ]);
    for (const value of document.querySelectorAll(".view-tech-wrap .tally-item .odometer-value")) {
      expect(value.getAttribute("aria-hidden")).not.toBe("true");
    }
    for (const strips of document.querySelectorAll(".view-tech-wrap .odometer-strips")) {
      expect(strips.getAttribute("aria-hidden")).toBe("true");
    }
    // The marks and the one-filter-per-box reading stay as they were.
    const marks = Array.from(
      document.querySelectorAll(".view-tech-wrap .tally-item .mark"),
    ).map((node) => node.className);
    expect(marks).toEqual(["mark mark-found", "mark mark-not_found", "mark mark-unmeasured"]);
  });
});
