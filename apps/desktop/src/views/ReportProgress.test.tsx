// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// E3: a scroll-progress line and one dot per collector group, both only while the technical view is
// shown. The line is decoration; each dot is a real link named by its group's heading.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import i18n, { initI18n } from "../i18n";
import type { ReportView } from "../types";
import { Report } from "./Report";
import { ReportProgress } from "./ReportProgress";

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

/** The window and document heights the progress maths reads. */
function setScroll(y: number, height = 2_000, viewport = 1_000): void {
  Object.defineProperty(window, "scrollY", { configurable: true, value: y });
  Object.defineProperty(window, "innerHeight", { configurable: true, value: viewport });
  Object.defineProperty(document.documentElement, "scrollHeight", {
    configurable: true,
    value: height,
  });
}

/** Replaces `window.matchMedia` with one that answers the reduced-motion query as `reduced`. */
function stubReducedMotion(reduced: boolean): void {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: (query: string) => ({
      matches: query === "(prefers-reduced-motion: reduce)" && reduced,
    }),
  });
}

/** Gives one heading a viewport position, so the 40 % test can be driven without layout. */
function placeHeading(id: string, top: number): void {
  const heading = document.getElementById(id);
  if (!heading) throw new Error(`no heading #${id}`);
  heading.getBoundingClientRect = () => ({ top }) as DOMRect;
}

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
  setScroll(0);
  stubReducedMotion(false);
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
  Reflect.deleteProperty(window, "matchMedia");
  Reflect.deleteProperty(HTMLElement.prototype, "scrollIntoView");
});

async function renderTechnical() {
  render(<Report mode="self" onBack={() => {}} />);
  await screen.findByText("Overview Summary");
  fireEvent.click(screen.getByRole("button", { name: "Detailed Report" }));
  const nav = document.querySelector<HTMLElement>("nav.report-progress-dots");
  if (!nav) throw new Error("no dot navigation");
  return nav;
}

describe("Report progress (E3)", () => {
  it("fills one thin line in proportion to the reader's scroll position", async () => {
    await renderTechnical();
    const line = document.querySelector<HTMLElement>(".report-progress-line");
    expect(line).not.toBeNull();
    expect(line?.getAttribute("aria-hidden")).toBe("true");

    setScroll(750);
    fireEvent.scroll(window);
    await waitFor(() => expect(line?.style.transform).toBe("scaleX(0.75)"));

    // Past the end the line stops at full, never overshooting.
    setScroll(5_000);
    fireEvent.scroll(window);
    await waitFor(() => expect(line?.style.transform).toBe("scaleX(1)"));

    // The summary view unmounts both decorations rather than hiding them.
    fireEvent.click(screen.getByRole("button", { name: "Overview Summary" }));
    expect(document.querySelector(".report-progress-line, .report-progress-dots")).toBeNull();
  });

  it("shows one dot per collector group, each named by its group heading", async () => {
    const nav = await renderTechnical();
    expect(nav.getAttribute("aria-label")).toBe("Report sections");
    const links = Array.from(nav.querySelectorAll<HTMLAnchorElement>("a"));
    expect(links).toHaveLength(GROUP_COUNT);

    for (const link of links) {
      const href = link.getAttribute("href");
      if (!href) throw new Error("dot without an href");
      const heading = document.getElementById(href.slice(1));
      expect(heading?.tagName).toBe("H3");
      expect(within(nav).getByRole("link", { name: heading?.textContent ?? "" })).toBe(link);
    }

    // Fewer than two groups have nothing to jump between, so no dots.
    cleanup();
    const { container } = render(<ReportProgress groups={[{ collector: "posture", rows: [] }]} />);
    expect(container.querySelector(".report-progress-line")).not.toBeNull();
    expect(container.querySelector(".report-progress-dots")).toBeNull();
  });

  it("scrolls to a group, focuses its heading, and moves aria-current with the view", async () => {
    const nav = await renderTechnical();
    const links = Array.from(nav.querySelectorAll<HTMLAnchorElement>("a"));
    const scrollIntoView = vi.fn();
    Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
      configurable: true,
      value: scrollIntoView,
    });

    const second = links[1];
    if (!second) throw new Error("the snapshot needs two groups");
    const href = second.getAttribute("href");
    if (!href) throw new Error("dot without an href");
    const secondHeading = document.getElementById(href.slice(1));
    fireEvent.click(second);
    expect(document.activeElement).toBe(secondHeading);
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: "smooth", block: "start" });

    // The first two headings are above 40 % of a 1000 px viewport; the last one wins.
    links.forEach((link, index) => {
      const target = link.getAttribute("href");
      if (target) placeHeading(target.slice(1), index < 2 ? 100 + index * 100 : 900);
    });
    fireEvent.scroll(window);
    await waitFor(() => expect(links[1]?.getAttribute("aria-current")).toBe("true"));
    expect(links[0]?.getAttribute("aria-current")).toBeNull();

    // Push the second group below the 40 % line: the first becomes the group in view.
    if (href) placeHeading(href.slice(1), 900);
    fireEvent.scroll(window);
    await waitFor(() => expect(links[0]?.getAttribute("aria-current")).toBe("true"));
    expect(links[1]?.getAttribute("aria-current")).toBeNull();
  });

  it("scrolls without easing but still follows scroll under reduced motion", async () => {
    stubReducedMotion(true);
    const nav = await renderTechnical();
    const first = nav.querySelector<HTMLAnchorElement>("a");
    if (!first) throw new Error("no dot");
    const scrollIntoView = vi.fn();
    Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
      configurable: true,
      value: scrollIntoView,
    });

    fireEvent.click(first);
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: "auto", block: "start" });

    const line = document.querySelector<HTMLElement>(".report-progress-line");
    setScroll(500);
    fireEvent.scroll(window);
    await waitFor(() => expect(line?.style.transform).toBe("scaleX(0.5)"));
  });
});
