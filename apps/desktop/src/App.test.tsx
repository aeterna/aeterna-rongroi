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
import type { ReportHeader, ReportView } from "./types";

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/rongroi-collectors/tests/snapshots");

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

const RULE_ID = "7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7";
const ENGLISH_RETENTION =
  "Current setting only. It says nothing about how the PC was configured in the past.";
const THAI_RETENTION = "เป็นค่าที่ตั้งไว้ตอนนี้เท่านั้น บอกไม่ได้ว่าในอดีตเครื่องนี้เคยตั้งค่าไว้อย่างไร";
const selfView = snapshot("secure_boot_off_self_view");
const ssView = snapshot("secure_boot_off_ss_view");
let calls: string[] = [];
let viewOverride: ReportView | null = null;
let headerOverride: ReportHeader | null = null;

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  calls = [];
  viewOverride = null;
  headerOverride = null;
  await i18n.changeLanguage("en");
  mockIPC((cmd, args) => {
    calls.push(cmd);
    const payload = (args ?? {}) as Record<string, unknown>;
    switch (cmd) {
      case "report_header":
        return headerOverride ?? selfView.header;
      case "report_view":
        return viewOverride ?? (payload.mode === "ss" ? ssView : selfView);
      case "rule_texts":
        return {
          [RULE_ID]: {
            title: payload.lang === "th" ? "Secure Boot ถูกปิดอยู่" : "Secure Boot is turned off",
            description: "",
            falsepositives: [],
            retention: payload.lang === "th" ? THAI_RETENTION : ENGLISH_RETENTION,
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
    // One not-found rule is hidden: `tpm-absent` is `context` strength, and SS mode lists a context
    // rule only when it matches, while posture rules are listed whatever their state (ADR 0011).
    expect(
      screen.getByText(
        "Hidden in SS mode: 1 not found · 0 not measured · 0 unmatched observations",
      ),
    ).toBeTruthy();
    expect(calls).toContain("report_view");
  });

  it("shows the program version in the report header, which the release notes ask people to check", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    expect(await screen.findByText("Version")).toBeTruthy();
    expect(screen.getByText(selfView.header.provenance.version)).toBeTruthy();
  });

  it("offers the administrator restart when the scan ran without administrator rights", async () => {
    render(<App />);
    expect(await screen.findByText("Scan as administrator")).toBeTruthy();
  });

  it("does not offer the administrator restart when the scan already had those rights", async () => {
    headerOverride = { ...selfView.header, elevated: true };
    render(<App />);
    // The banner proves the header arrived, so the button is absent by choice and not by timing.
    await screen.findByRole("alert");
    expect(screen.queryByText("Scan as administrator")).toBeNull();
  });

  it("does not offer the administrator restart before the header has loaded", () => {
    render(<App />);
    expect(screen.queryByText("Scan as administrator")).toBeNull();
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

  it("lists what the tool itself left, apart from the evidence", async () => {
    viewOverride = {
      ...selfView,
      own_traces: [
        {
          collector: "process",
          observation: {
            collector: "process",
            fields: {
              name: "aeterna-rongroi.exe",
              path: "%USERPROFILE%\\Downloads\\aeterna-rongroi.exe",
            },
          },
        },
      ],
    };
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    const section = await screen.findByRole("region", { name: "Own traces (excluded)" });
    expect(section.textContent).toContain("aeterna-rongroi.exe");
    // The evidence list above it is untouched.
    expect(screen.getByText("Check: Secure Boot is turned off")).toBeTruthy();
  });

  it("lists what the collectors saw that no rule matched, apart from the evidence", async () => {
    viewOverride = {
      ...selfView,
      unmatched: [
        {
          collector: "fivem_dir",
          observations: [
            {
              collector: "fivem_dir",
              fields: {
                location: "plugins",
                path: "C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\plugins\\overlay.dll",
              },
            },
          ],
        },
      ],
    };
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    const section = await screen.findByRole("region", { name: "Unmatched observations" });
    expect(section.textContent).toContain("overlay.dll");
    // The evidence list above it is untouched.
    expect(screen.getByText("Check: Secure Boot is turned off")).toBeTruthy();
  });

  it("shows no unmatched section when every observation matched a rule", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    // The evidence proves the view arrived, so the section is absent by choice and not by timing.
    await screen.findByText("Check: Secure Boot is turned off");
    expect(screen.queryByRole("region", { name: "Unmatched observations" })).toBeNull();
  });

  it("shows the look-back note of not-found evidence in the chosen language", async () => {
    const first = selfView.evidence[0];
    if (!first) {
      throw new Error("the self-view snapshot has no evidence");
    }
    viewOverride = {
      ...selfView,
      evidence: [
        {
          rule_id: first.rule_id,
          collector: first.collector,
          strength: first.strength,
          state: "not_found",
          retention: ENGLISH_RETENTION,
        },
      ],
    };
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage("th");
    });
    fireEvent.click(await screen.findByText("ตรวจเครื่องตัวเอง"));
    expect(await screen.findByText(`ย้อนดูได้: ${THAI_RETENTION}`)).toBeTruthy();
    expect(screen.queryByText(ENGLISH_RETENTION, { exact: false })).toBeNull();
  });
});
