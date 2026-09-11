// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// L4: the UI renders the same report the Rust pipeline produces (the insta snapshots), through mocked IPC.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { App } from "./App";
import i18n, { initI18n } from "./i18n";
import type { ReportView } from "./types";

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/rongroi-collectors/tests/snapshots");

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

const RULE_ID = "7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7";
const selfView = snapshot("secure_boot_off_self_view");
const ssView = snapshot("secure_boot_off_ss_view");
let calls: string[] = [];

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  calls = [];
  await i18n.changeLanguage("en");
  mockIPC((cmd, args) => {
    calls.push(cmd);
    const payload = (args ?? {}) as Record<string, unknown>;
    switch (cmd) {
      case "report_header":
        return selfView.header;
      case "report_view":
        return payload.mode === "ss" ? ssView : selfView;
      case "rule_texts":
        return {
          [RULE_ID]: {
            title: payload.lang === "th" ? "Secure Boot ถูกปิดอยู่" : "Secure Boot is turned off",
            description: "",
            falsepositives: [],
          },
        };
      default:
        throw new Error(`unexpected command ${cmd}`);
    }
  });
});

afterEach(() => {
  cleanup();
  clearMocks();
});

describe("App", () => {
  it("snapshots are the Rust pipeline output", () => {
    expect(selfView.mode).toBe("self");
    expect(ssView.mode).toBe("ss");
    expect(selfView.evidence[0]?.rule_id).toBe(RULE_ID);
  });

  it("announces an unofficial build on the start screen", async () => {
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      expect.stringContaining("UNOFFICIAL BUILD"),
    );
  });

  it("shows nothing from the report when SS consent is refused", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Screenshare check (SS mode)"));
    expect(screen.getByText("You may refuse.")).toBeTruthy();
    fireEvent.click(screen.getByText("I refuse"));
    expect(screen.getByText("Nothing was shown")).toBeTruthy();
    expect(calls).not.toContain("report_view");
  });

  it("shows the SS view with hidden counts after consent", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Screenshare check (SS mode)"));
    fireEvent.click(screen.getByText("I agree — show the SS view"));
    expect(await screen.findByText("Found")).toBeTruthy();
    expect(await screen.findByText("Check: Secure Boot is turned off")).toBeTruthy();
    expect(screen.getByText("Hidden in SS mode: 0 not found · 0 not measured")).toBeTruthy();
    expect(calls).toContain("report_view");
  });

  it("switches to Thai, keeping the UNOFFICIAL BUILD token in English", async () => {
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage("th");
    });
    fireEvent.click(await screen.findByText("ตรวจเครื่องตัวเอง"));
    expect(await screen.findByText("ตรวจ: Secure Boot ถูกปิดอยู่")).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain("UNOFFICIAL BUILD");
  });
});
