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
import type { ReportHeader, ReportView, UnmeasuredReason } from "./types";

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
// Both are mandatory in every rule and CI rejects a rule that leaves either empty, so the mock
// carries them the way the real bundle does (ADR 0027).
const ENGLISH_DESCRIPTION = "Windows reports that UEFI Secure Boot is off.";
const THAI_DESCRIPTION = "Windows รายงานว่า UEFI Secure Boot ปิดอยู่";
const ENGLISH_FALSEPOSITIVE = "PCs that boot in legacy BIOS or CSM mode";
const THAI_FALSEPOSITIVE = "เครื่องที่บูตแบบ legacy BIOS หรือ CSM";
const selfView = snapshot("secure_boot_off_self_view");
const ssView = snapshot("secure_boot_off_ss_view");

// The evidence entry these tests build their overrides from: the Secure Boot rule, found by id
// rather than taken as `evidence[0]`. Every assertion below is about that rule's own text, and the
// order of the evidence list is the order of the rules bundle — which changes whenever a rule is
// added, as `rules/evtx/` did.
function subject(view: ReportView) {
  const found = view.evidence.find((item) => item.rule_id === RULE_ID);
  if (!found) {
    throw new Error(`the snapshot has no evidence for ${RULE_ID}`);
  }
  return found;
}
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
            description: payload.lang === "th" ? THAI_DESCRIPTION : ENGLISH_DESCRIPTION,
            falsepositives: [payload.lang === "th" ? THAI_FALSEPOSITIVE : ENGLISH_FALSEPOSITIVE],
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
    expect(subject(selfView).rule_id).toBe(RULE_ID);
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
        "Hidden in SS mode: 1 not found · 0 not measured (expected) · 0 not measured (not expected) · 0 unmatched observations",
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

  // A match shown without what else produces it is a match shown as an accusation. Both halves are
  // written in every rule and translated, and neither reached a screen before (ADR 0027).
  it("shows a found entry's description and its false positives", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    await screen.findByText("Check: Secure Boot is turned off");
    expect(screen.getByText(`About this check: ${ENGLISH_DESCRIPTION}`)).toBeTruthy();
    expect(screen.getByText("Ordinary things that also produce this:")).toBeTruthy();
    expect(screen.getByText(ENGLISH_FALSEPOSITIVE)).toBeTruthy();
  });

  it("shows a found entry's description and its false positives in Thai", async () => {
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage("th");
    });
    fireEvent.click(await screen.findByText("ตรวจเครื่องตัวเอง"));
    await screen.findByText("ตรวจ: Secure Boot ถูกปิดอยู่");
    expect(screen.getByText(`เกี่ยวกับการตรวจนี้: ${THAI_DESCRIPTION}`)).toBeTruthy();
    expect(screen.getByText("เรื่องปกติที่ทำให้เกิดผลแบบนี้ได้เหมือนกัน:")).toBeTruthy();
    expect(screen.getByText(THAI_FALSEPOSITIVE)).toBeTruthy();
  });

  // `description` says what the check is, which a reader needs whatever the answer was;
  // `falsepositives` explains a match, and nothing matched.
  it("shows the description but no false positives beside a not-found entry", async () => {
    const first = subject(selfView);
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
    fireEvent.click(await screen.findByText("Check my own PC"));
    expect(await screen.findByText(`About this check: ${ENGLISH_DESCRIPTION}`)).toBeTruthy();
    expect(screen.queryByText("Ordinary things that also produce this:")).toBeNull();
    expect(screen.queryByText(ENGLISH_FALSEPOSITIVE)).toBeNull();
  });

  // The whole of what `unmeasured_when` does to a view: a reason the rule named is a number, a
  // reason it did not name is a row (ADR 0027).
  it("lists the unmeasured result its rule did not expect and counts the one it did", async () => {
    const first = subject(selfView);
    viewOverride = {
      ...ssView,
      evidence: [
        {
          rule_id: first.rule_id,
          collector: first.collector,
          strength: first.strength,
          state: "unmeasured",
          reason: "read_failed",
          expected: false,
        },
      ],
      hidden: { ...ssView.hidden, unmeasured_expected: 3 },
    };
    render(<App />);
    fireEvent.click(await screen.findByText("Screenshare check (SS mode)"));
    fireEvent.click(screen.getByText("I agree — show the SS view"));
    expect(await screen.findByText("Not measured (not expected)")).toBeTruthy();
    expect(
      screen.getByText(
        "Hidden in SS mode: 1 not found · 3 not measured (expected) · 0 not measured (not expected) · 0 unmatched observations",
      ),
    ).toBeTruthy();
  });

  // One fact about the scan that applies to every rule at once, and the one unmeasured reason with
  // a remedy, so it is stated once above the evidence (ADR 0012, ADR 0027).
  it("states missing administrator rights once, above the evidence", async () => {
    viewOverride = { ...selfView, scope: { not_admin: 2, not_attempted: 0 } };
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    const statements = await screen.findAllByText(/could not be answered because this scan/);
    expect(statements).toHaveLength(1);
    expect(statements[0]?.textContent).toContain("2 check(s)");
  });

  // The second scope statement, and the same shape for the same reason: a source this program
  // stopped short of is one fact about how far the scan got, and it says so about the program and
  // never about the PC (ADR 0030).
  it("states the sources it never reached once, above the evidence", async () => {
    viewOverride = { ...selfView, scope: { not_admin: 0, not_attempted: 3 } };
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    const statements = await screen.findAllByText(/this program stopped reading before/);
    expect(statements).toHaveLength(1);
    expect(statements[0]?.textContent).toContain("3 check(s)");
    expect(statements[0]?.textContent).toContain("not a finding about this PC");
  });

  // Each of the twelve reasons reaches a reader as a sentence, never as its identifier: a row
  // reading `source_empty` is a row that says nothing to the person it is about (ADR 0030).
  it.each([
    ["not_on_this_os", "this version of Windows does not keep this record"],
    ["not_attempted", "the scan stopped before reaching it"],
    ["service_disabled", "the Windows service that writes this record is switched off"],
    ["source_absent", "this PC has no such record to read"],
    ["source_empty", "the place this is kept is there and holds nothing"],
    ["partial", "part of this was read and part of it was not"],
    ["budget_spent", "this program stopped reading before it finished"],
  ])("shows %s as a sentence a non-expert reads", async (reason, sentence) => {
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
          state: "unmeasured",
          reason: reason as UnmeasuredReason,
          expected: false,
        },
      ],
    };
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    expect(await screen.findByText(new RegExp(sentence))).toBeTruthy();
  });

  it("states nothing about administrator rights when every check was answerable", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    // The evidence proves the view arrived, so the statement is absent by choice and not by timing.
    await screen.findByText("Check: Secure Boot is turned off");
    expect(screen.queryByText(/could not be answered because this scan/)).toBeNull();
  });

  it("shows the look-back note of not-found evidence in the chosen language", async () => {
    const first = subject(selfView);
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
