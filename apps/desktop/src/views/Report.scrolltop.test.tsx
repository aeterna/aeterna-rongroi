// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// A report can run for pages; the way back to its top appears only once the reader has scrolled.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
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
const originalMatchMedia = Object.getOwnPropertyDescriptor(window, "matchMedia");

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
  Object.defineProperty(window, "scrollY", { configurable: true, value: 0 });
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn().mockReturnValue({ matches: false }),
  });
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
  if (originalMatchMedia) {
    Object.defineProperty(window, "matchMedia", originalMatchMedia);
  } else {
    Reflect.deleteProperty(window, "matchMedia");
  }
});

describe("Report scroll-to-top", () => {
  it("stays hidden at the top and appears after the page is scrolled, then scrolls up smoothly", async () => {
    render(<Report mode="self" onBack={() => {}} />);
    await screen.findByText("Overview Summary");
    expect(screen.queryByRole("button", { name: "Back to top" })).toBeNull();

    Object.defineProperty(window, "scrollY", { configurable: true, value: 250 });
    fireEvent.scroll(window);
    const button = screen.getByRole("button", { name: "Back to top" });

    const scrollTo = vi.spyOn(window, "scrollTo").mockImplementation(() => {});
    fireEvent.click(button);
    expect(scrollTo).toHaveBeenCalledWith({ top: 0, behavior: "smooth" });

    Object.defineProperty(window, "scrollY", { configurable: true, value: 0 });
    fireEvent.scroll(window);
    expect(screen.queryByRole("button", { name: "Back to top" })).toBeNull();
  });

  it("scrolls without animation when reduced motion is requested", async () => {
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({ matches: true }),
    });
    render(<Report mode="self" onBack={() => {}} />);
    await screen.findByText("Overview Summary");

    Object.defineProperty(window, "scrollY", { configurable: true, value: 250 });
    fireEvent.scroll(window);
    const scrollTo = vi.spyOn(window, "scrollTo").mockImplementation(() => {});
    fireEvent.click(screen.getByRole("button", { name: "Back to top" }));
    expect(scrollTo).toHaveBeenCalledWith({ top: 0, behavior: "auto" });
  });
});
