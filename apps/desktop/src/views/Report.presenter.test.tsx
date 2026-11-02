// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// E10: presenter mode is offered only by the SS technical view, moves by position with the arrow,
// Home and End keys, and dims the other groups without removing or hiding them.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "../api";
import i18n, { initI18n } from "../i18n";
import type { ReportView } from "../types";
import { Report } from "./Report";

vi.mock("../api", () => ({
  ageTexts: vi.fn(),
  codeLinkQr: vi.fn(),
  codeLinks: vi.fn(),
  reportView: vi.fn(),
  ruleTexts: vi.fn(),
  saveSavedRecord: vi.fn(),
}));

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/rongroi-collectors/tests/snapshots");

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

const VIEW = snapshot("secure_boot_off_ss_view");

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
  vi.mocked(api.reportView).mockResolvedValue(VIEW);
  vi.mocked(api.ruleTexts).mockResolvedValue({});
  vi.mocked(api.ageTexts).mockResolvedValue({});
  vi.mocked(api.codeLinks).mockResolvedValue({ repository: "r", code: "r", commit: null });
});

afterEach(() => {
  cleanup();
  for (const overlay of document.querySelectorAll(".palette-backdrop, [role=dialog]")) {
    overlay.remove();
  }
  vi.clearAllMocks();
});

/** Renders the report in `mode` and waits for its view; both view bodies are in the DOM. */
async function renderReport(mode: "ss" | "self") {
  render(<Report mode={mode} onBack={() => {}} />);
  await screen.findByText("Overview Summary");
}

function openTechnical(): void {
  fireEvent.click(screen.getByRole("button", { name: "Detailed Report" }));
}

/** The evidence groups in their rendered order. */
function groupElements(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>(".view-tech-wrap section.group"));
}

/** Asserts exactly one current group at `index` and every other group dim. */
function expectCurrentAt(index: number): void {
  const groups = groupElements();
  expect(groups.length).toBeGreaterThan(index);
  groups.forEach((group, groupIndex) => {
    expect(group.dataset.presenter).toBe(groupIndex === index ? "current" : "dim");
  });
}

function presenterToggle(): HTMLElement {
  return screen.getByRole("button", { name: "Presenter" });
}

describe("Report presenter (E10)", () => {
  it("offers the toggle only in the SS technical view", async () => {
    await renderReport("ss");
    expect(screen.queryByRole("button", { name: "Presenter" })).toBeNull();

    openTechnical();
    expect(presenterToggle()).not.toBeNull();

    // The same technical view in self mode never offers presenter mode at all.
    cleanup();
    await renderReport("self");
    openTechnical();
    expect(screen.queryByRole("button", { name: "Presenter" })).toBeNull();
  });

  it("moves with ArrowRight, ArrowLeft, Home and End and dims the others", async () => {
    await renderReport("ss");
    openTechnical();
    const total = groupElements().length;
    expect(total).toBeGreaterThan(2);

    fireEvent.click(presenterToggle());
    expectCurrentAt(0);

    // Dimming is positional and cosmetic: every other group is still in the document, reachable
    // and in the accessibility tree.
    const dimmed = groupElements().filter((group) => group.dataset.presenter === "dim");
    expect(dimmed).toHaveLength(total - 1);
    for (const group of dimmed) {
      expect(document.body.contains(group)).toBe(true);
      expect(group.hasAttribute("inert")).toBe(false);
      expect(group.getAttribute("aria-hidden")).toBeNull();
    }

    fireEvent.keyDown(window, { key: "ArrowRight" });
    expectCurrentAt(1);
    fireEvent.keyDown(window, { key: "ArrowRight" });
    expectCurrentAt(2);
    fireEvent.keyDown(window, { key: "ArrowLeft" });
    expectCurrentAt(1);
    fireEvent.keyDown(window, { key: "End" });
    expectCurrentAt(total - 1);
    fireEvent.keyDown(window, { key: "Home" });
    expectCurrentAt(0);
  });

  it("leaves the position alone while focus is in the search input", async () => {
    await renderReport("ss");
    openTechnical();
    fireEvent.click(presenterToggle());
    expectCurrentAt(0);

    const search = screen.getByRole("searchbox", { name: "Search checks" });
    search.focus();
    fireEvent.keyDown(search, { key: "ArrowRight" });
    fireEvent.keyDown(search, { key: "End" });
    expectCurrentAt(0);
  });

  it("ignores keys behind the palette backdrop but not behind an unrelated dialog", async () => {
    await renderReport("ss");
    openTechnical();
    fireEvent.click(presenterToggle());
    expectCurrentAt(0);

    const backdrop = document.createElement("div");
    backdrop.className = "palette-backdrop";
    document.body.append(backdrop);
    fireEvent.keyDown(window, { key: "ArrowRight" });
    expectCurrentAt(0);
    backdrop.remove();

    // A non-modal drawer also has role=dialog, but only the command palette owns the keys.
    const drawer = document.createElement("div");
    drawer.setAttribute("role", "dialog");
    document.body.append(drawer);
    fireEvent.keyDown(window, { key: "ArrowRight" });
    expectCurrentAt(1);
    drawer.remove();
  });

  it("turns presenter mode off on Escape and clears every presenter mark", async () => {
    await renderReport("ss");
    openTechnical();
    fireEvent.click(presenterToggle());
    expectCurrentAt(0);

    fireEvent.keyDown(window, { key: "Escape" });
    expect(document.querySelectorAll("[data-presenter]")).toHaveLength(0);
    expect(presenterToggle().getAttribute("aria-pressed")).toBe("false");
  });

  it("shows the first position and the group total in the counter", async () => {
    await renderReport("ss");
    openTechnical();
    const total = groupElements().length;
    expect(total).toBeGreaterThan(1);

    fireEvent.click(presenterToggle());
    expect(document.querySelector(".presenter-counter")?.textContent).toBe(`1 / ${total}`);

    fireEvent.keyDown(window, { key: "ArrowRight" });
    expect(document.querySelector(".presenter-counter")?.textContent).toBe(`2 / ${total}`);
  });

  it("keeps dim opacity readable without blur, grayscale, visibility or display none", () => {
    const css = readFileSync(resolve(process.cwd(), "src/views/Report.presenter.css"), "utf8");
    // Comments may name a forbidden effect ("never a blur"); only declarations can apply one.
    const declarations = css.replace(/\/\*[\s\S]*?\*\//g, "");
    const opacities = [...declarations.matchAll(/opacity\s*:\s*([^;}]+)/gi)].map((match) =>
      (match[1] ?? "").trim(),
    );
    expect(opacities.length).toBeGreaterThan(0);
    for (const value of opacities) {
      expect(Number.isFinite(Number(value))).toBe(true);
      expect(Number(value)).toBeGreaterThanOrEqual(0.6);
    }
    expect(declarations).not.toMatch(/blur|grayscale|visibility|display\s*:\s*none/i);
  });
});
