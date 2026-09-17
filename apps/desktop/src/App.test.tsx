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
import type { ReportHeader, ReportView, RuleText, UnmeasuredReason } from "./types";

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
/** Rule texts added to the mocked `rule_texts` answer, for tests that need a timeline selector's. */
let extraTexts: Record<string, RuleText> = {};
let headerOverride: ReportHeader | null = null;
let linksOverride: { repository: string; code: string; commit: string | null } | null = null;
// Carried fix (b): a `code_links` call that never resolves, so `links` stays `null` — the same shape
// the UI sees while the call is still in flight or after it failed.
let linksNeverResolve = false;
let clipboardWrites: string[] = [];
const REPOSITORY = "https://github.com/aeterna/aeterna-rongroi";
const COMMIT = "2c673c54aeb084cd3773057efbb9ed3b98fd2dbc";
// Carried fix (d): the real descriptor before any test stubs it, so it can be restored afterwards
// instead of leaking a fake `navigator.clipboard` into the next test file.
const originalClipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard");

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  calls = [];
  viewOverride = null;
  extraTexts = {};
  headerOverride = null;
  linksOverride = null;
  linksNeverResolve = false;
  clipboardWrites = [];
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
          ...extraTexts,
          [RULE_ID]: {
            title: payload.lang === "th" ? "Secure Boot ถูกปิดอยู่" : "Secure Boot is turned off",
            description: payload.lang === "th" ? THAI_DESCRIPTION : ENGLISH_DESCRIPTION,
            falsepositives: [payload.lang === "th" ? THAI_FALSEPOSITIVE : ENGLISH_FALSEPOSITIVE],
            retention: payload.lang === "th" ? THAI_RETENTION : ENGLISH_RETENTION,
            status: "test",
            files: {
              rule: "rules/posture/boot/secure-boot-disabled/rule.yaml",
              fixtures: "rules/posture/boot/secure-boot-disabled/tests",
              collector: "crates/rongroi-collectors/src/posture.rs",
              references: [],
            },
          },
        };
      case "code_links":
        if (linksNeverResolve) {
          return new Promise(() => {});
        }
        return linksOverride ?? { repository: REPOSITORY, code: REPOSITORY, commit: null };
      case "code_link_qr":
        return `<?xml version="1.0" standalone="yes"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`;
      default:
        throw new Error(`unexpected command ${cmd}`);
    }
  });
});

afterEach(() => {
  cleanup();
  clearMocks();
  if (originalClipboardDescriptor) {
    Object.defineProperty(navigator, "clipboard", originalClipboardDescriptor);
  } else {
    // jsdom had no `navigator.clipboard` of its own before any test stubbed it.
    (navigator as { clipboard?: unknown }).clipboard = undefined;
  }
});

/** Opens a closed row by clicking its title. */
function openRow(title: string) {
  fireEvent.click(screen.getByText(title));
}

function stubClipboard(result: "ok" | "refused") {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: (text: string) => {
        if (result === "refused") {
          return Promise.reject(new Error("refused"));
        }
        clipboardWrites.push(text);
        return Promise.resolve();
      },
    },
  });
}

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

  // ADR 0051: the SS view shows its timeline, with what it never says above it, and the scan's own
  // time as an anchor.
  it("shows the timeline in SS mode with its note and the scan time", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Screenshare check (SS mode)"));
    fireEvent.click(screen.getByText("I agree — show the SS view"));
    expect(await screen.findByText("Timeline")).toBeTruthy();
    expect(screen.getByText(/An order of recorded times is not an order of events/)).toBeTruthy();
    expect(screen.getByText("This scan ran")).toBeTruthy();
    expect(screen.getByText(ssView.header.generated_at)).toBeTruthy();
  });

  it("names the selector behind a selected time and its ordinary causes", async () => {
    viewOverride = {
      ...ssView,
      timeline: {
        entries: [
          {
            at: "2026-09-15T18:02:11Z",
            collector: "prefetch",
            field: "last_run",
            place: null,
            source: { kind: "selector", selector_id: "selector-id" },
            subject: "FIVEM.EXE",
          },
        ],
        bands: [],
        unmeasured: [{ collector: "usn", reason: "not_admin" }],
      },
    };
    extraTexts = {
      "selector-id": {
        title: "When Prefetch recorded a program named like FiveM or GTA V",
        description: "Puts a time on the timeline.",
        falsepositives: ["Any program of one of these names"],
        retention: "Only the Prefetch files still in the folder.",
        status: "experimental",
        files: { rule: "r", fixtures: "f", collector: "c", references: [] },
      },
    };
    render(<App />);
    fireEvent.click(await screen.findByText("Screenshare check (SS mode)"));
    fireEvent.click(screen.getByText("I agree — show the SS view"));
    expect(await screen.findByText(/Windows Prefetch · FIVEM\.EXE/)).toBeTruthy();
    expect(
      screen.getAllByText(/When Prefetch recorded a program named like FiveM or GTA V/).length,
    ).toBe(2);
    expect(screen.getByText("Any program of one of these names")).toBeTruthy();
    expect(
      screen.getByText(
        "NTFS change journal: not measured — Windows would not show this without administrator rights",
      ),
    ).toBeTruthy();
  });

  it("shows nothing from the report when SS consent is refused", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Screenshare check (SS mode)"));
    expect(screen.getByText("You may refuse.")).toBeTruthy();
    // The scan ran before this screen, so consent has to say what it read, not only settings.
    expect(
      screen.getByText(/what Windows recorded about programs that ran \(Prefetch, BAM/),
    ).toBeTruthy();
    // ADR 0051: what the SS timeline shows is named, program by program.
    expect(
      screen.getByText(
        /a timeline of: .*GTA5_Enhanced\.exe, PlayGTAV\.exe or FiveM_b<number>_GTAProcess\.exe/,
      ),
    ).toBeTruthy();
    // The boot time is not a collector, and staff see it at the top of the report (ADR 0039).
    expect(screen.getByText(/when Windows last started, which staff will see/)).toBeTruthy();
    expect(screen.getByText(/marked read-only/)).toBeTruthy();
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
    // One not-measured rule is hidden too: the firmware reading needs administrator rights, which this
    // fixture's scan did not have, so it is said once in the scope line rather than as a row (ADR 0038).
    expect(
      screen.getByText(
        "Hidden in SS mode: 1 not found · 1 not measured (expected) · 0 not measured (not expected) · 0 unmatched observations",
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

  // One line of context in the header, in both modes, with the caveat beside it that stops a start
  // days before the scan being read as something the player did (ADR 0039).
  it.each([
    ["Check my own PC", null],
    ["Screenshare check (SS mode)", "I agree — show the SS view"],
  ])("shows when Windows started, with its caveat, after %s", async (open, agree) => {
    render(<App />);
    fireEvent.click(await screen.findByText(open));
    if (agree) {
      fireEvent.click(screen.getByText(agree));
    }
    expect(await screen.findByText("Windows start")).toBeTruthy();
    expect(screen.getByText(/^2025-12-28T21:56:56Z, 3d 2h 3m before this scan\./)).toBeTruthy();
    expect(screen.getByText(/Not reset by "Shut down" with Fast Startup/)).toBeTruthy();
  });

  it("shows when Windows started in Thai", async () => {
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage("th");
    });
    fireEvent.click(await screen.findByText("ตรวจเครื่องตัวเอง"));
    expect(await screen.findByText("Windows เริ่มทำงาน")).toBeTruthy();
    expect(
      screen.getByText(/^2025-12-28T21:56:56Z \(3 วัน 2 ชม\. 3 นาที ก่อนการสแกนนี้\)/),
    ).toBeTruthy();
  });

  // No time where none was measured, and the reason in the words every unmeasured row uses.
  it("shows an unmeasured boot time as a reason and no time", async () => {
    viewOverride = {
      ...selfView,
      header: { ...selfView.header, boot_time: { state: "unmeasured", reason: "not_windows" } },
    };
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    expect(await screen.findByText("not measured — not running on Windows")).toBeTruthy();
    expect(screen.queryByText(/before this scan/)).toBeNull();
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
    fireEvent.click(await screen.findByText("Not found: 1 — show what was checked"));
    openRow("Check: Secure Boot is turned off");
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
      // The row is what this test reads; the timeline states its own unmeasured sources.
      timeline: { ...selfView.timeline, unmeasured: [] },
    };
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    fireEvent.click(await screen.findByText(/^Check: /));
    expect(await screen.findByText(new RegExp(sentence))).toBeTruthy();
  });

  it("states nothing about administrator rights when every check was answerable", async () => {
    // The snapshot's own scan could not read the firmware without those rights (ADR 0038), so the
    // answerable case is written here: the same view with no rule stopped by them.
    viewOverride = { ...selfView, scope: { not_admin: 0, not_attempted: 0 } };
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
    fireEvent.click(await screen.findByText("ไม่เจอ 1 รายการ — กดเพื่อดูว่าตรวจอะไรไปบ้าง"));
    fireEvent.click(screen.getByText("ตรวจ: Secure Boot ถูกปิดอยู่"));
    expect(await screen.findByText(`ย้อนดูได้: ${THAI_RETENTION}`)).toBeTruthy();
    expect(screen.queryByText(ENGLISH_RETENTION, { exact: false })).toBeNull();
  });

  // Three counts of states and the sentence that no report proves a PC clean, above the rows; never
  // one number (ADR 0002, ADR 0045).
  it("lists how many rows are in each state, beside the sentence that it proves nothing clean", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    const summary = await screen.findByRole("region", { name: "What this scan lists" });
    const buttons = Array.from(summary.querySelectorAll("button"));
    expect(buttons.map((b) => b.textContent)).toEqual([
      `${selfView.listed.found}found — each one lists ordinary things that also produce it`,
      `${selfView.listed.not_found}not found — each row says how far back it can see`,
      `${selfView.listed.unmeasured}not measured — each row says why`,
    ]);
    expect(summary.textContent).toContain("This report cannot prove that a PC is clean.");
  });

  it("filters the rows to one state from its count", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    const summary = await screen.findByRole("region", { name: "What this scan lists" });
    const found = summary.querySelector("button");
    if (!found) throw new Error("no count");
    fireEvent.click(found);
    expect(found.getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByText("Check: Secure Boot is turned off")).toBeTruthy();
    expect(screen.queryByText(/— show what was checked$/)).toBeNull();
    fireEvent.click(screen.getByText("Show every state"));
    expect(found.getAttribute("aria-pressed")).toBe("false");
  });

  it("groups rows under a plain name for their collector", async () => {
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage("th");
    });
    fireEvent.click(await screen.findByText("ตรวจเครื่องตัวเอง"));
    expect(await screen.findByRole("region", { name: "การตั้งค่าความปลอดภัยของเครื่อง" })).toBeTruthy();
  });

  it("starts a not-found row closed, with the description cut short and not labelled", async () => {
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
    fireEvent.click(await screen.findByText("Not found: 1 — show what was checked"));
    const head = screen.getByText("Check: Secure Boot is turned off").closest("button");
    expect(head?.getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByText(ENGLISH_DESCRIPTION)).toBeTruthy();
    expect(screen.queryByText(`About this check: ${ENGLISH_DESCRIPTION}`)).toBeNull();
  });

  it("opens technical details and the rule's files at this build's commit", async () => {
    linksOverride = {
      repository: REPOSITORY,
      code: `${REPOSITORY}/tree/${COMMIT}`,
      commit: COMMIT,
    };
    stubClipboard("ok");
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    fireEvent.click(await screen.findByLabelText("Show technical details for every row"));
    expect(screen.getAllByText(RULE_ID).length).toBeGreaterThan(0);
    expect(screen.getAllByText("secure_boot").length).toBeGreaterThan(0);
    const rulePath = screen.getByText("rules/posture/boot/secure-boot-disabled/rule.yaml");
    const copy = rulePath.parentElement?.querySelector("button");
    if (!copy) throw new Error("no copy button");
    await act(async () => {
      fireEvent.click(copy);
    });
    expect(clipboardWrites).toEqual([
      `${REPOSITORY}/blob/${COMMIT}/rules/posture/boot/secure-boot-disabled/rule.yaml`,
    ]);
    expect(copy.textContent).toBe("Copied");
  });

  it("shows no file links for an unofficial build and says why", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    fireEvent.click(await screen.findByLabelText("Show technical details for every row"));
    const rulePath = await screen.findByText("rules/posture/boot/secure-boot-disabled/rule.yaml");
    expect(rulePath.parentElement?.querySelector("button")).toBeNull();
    expect(screen.getAllByText(/This build is not official/).length).toBeGreaterThan(0);
  });

  // An official build whose commit was not recorded is still official: the sentence says the commit
  // is not known, never that the build is not official.
  it("says the commit is not known, not that the build is unofficial, for an official build without one", async () => {
    const official = {
      ...selfView.header,
      provenance: { ...selfView.header.provenance, official: true, commit: null },
    };
    headerOverride = official;
    viewOverride = { ...selfView, header: official };
    linksOverride = { repository: REPOSITORY, code: REPOSITORY, commit: null };
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    fireEvent.click(await screen.findByLabelText("Show technical details for every row"));
    const rulePath = await screen.findByText("rules/posture/boot/secure-boot-disabled/rule.yaml");
    expect(rulePath.parentElement?.querySelector("button")).toBeNull();
    expect(
      (await screen.findAllByText(/The commit this program was built from is not known\./)).length,
    ).toBeGreaterThan(0);
    expect(screen.queryByText(/This build is not official/)).toBeNull();
  });

  // Carried fix (b): before `codeLinks()` has arrived (or after it has failed), the report does not
  // yet know whether this build is official, so it must not say either thing about the commit.
  it("says nothing about the build's commit before the code links resolve", async () => {
    linksNeverResolve = true;
    render(<App />);
    fireEvent.click(await screen.findByText("Check my own PC"));
    fireEvent.click(await screen.findByLabelText("Show technical details for every row"));
    const rulePath = await screen.findByText("rules/posture/boot/secure-boot-disabled/rule.yaml");
    expect(rulePath.parentElement?.querySelector("button")).toBeNull();
    expect(screen.queryByText(/This build is not official/)).toBeNull();
    expect(screen.queryByText(/At the commit this program was built from/)).toBeNull();
  });

  it("opens About & code from the start screen, with the repository and its QR code", async () => {
    stubClipboard("ok");
    render(<App />);
    fireEvent.click(await screen.findByText("About & code"));
    expect(await screen.findByText("About this program and its code")).toBeTruthy();
    expect(screen.getByText(REPOSITORY)).toBeTruthy();
    const qr = await screen.findByAltText(`QR code for ${REPOSITORY}`);
    expect(qr.getAttribute("src")).toMatch(/^data:image\/svg\+xml;charset=utf-8,/);
    // The snapshot's build is unofficial: its code is not known, and the page says so.
    expect(screen.getByText(/The code this build was made from is not known/)).toBeTruthy();
    // The window uses the consent screen's form of the ADR 0003 statement (`consent.sends`,
    // `consent.webview`), which ADR 0045 §7 keeps unchanged.
    expect(screen.getByText("aeterna-rongroi's own code sends nothing anywhere.")).toBeTruthy();
    await act(async () => {
      fireEvent.click(screen.getAllByText("Copy link")[0] as HTMLElement);
    });
    expect(clipboardWrites).toEqual([REPOSITORY]);
  });

  it("links the commit of an official build and the attestation command for its file", async () => {
    headerOverride = {
      ...selfView.header,
      provenance: { ...selfView.header.provenance, official: true, commit: COMMIT },
    };
    linksOverride = {
      repository: REPOSITORY,
      code: `${REPOSITORY}/tree/${COMMIT}`,
      commit: COMMIT,
    };
    render(<App />);
    fireEvent.click(await screen.findByText("About & code"));
    expect(await screen.findByText(`${REPOSITORY}/tree/${COMMIT}`)).toBeTruthy();
    expect(
      screen.getByText(
        `gh attestation verify aeterna-rongroi-${selfView.header.provenance.version}-windows-x64.exe -R aeterna/aeterna-rongroi`,
      ),
    ).toBeTruthy();
    expect(screen.queryByText(/The code this build was made from is not known/)).toBeNull();
  });

  it("says on About & code that an official build's commit is not known, without calling it unofficial", async () => {
    headerOverride = {
      ...selfView.header,
      provenance: { ...selfView.header.provenance, official: true, commit: null },
    };
    linksOverride = { repository: REPOSITORY, code: REPOSITORY, commit: null };
    render(<App />);
    fireEvent.click(await screen.findByText("About & code"));
    expect(
      await screen.findByText("The commit this build was made from is not known."),
    ).toBeTruthy();
    expect(screen.queryByText(/not built by the release workflow/)).toBeNull();
  });

  // About & code is reachable from every screen, so leaving it returns to the screen it was opened
  // from: an SS report stays an SS report, without asking for consent a second time.
  it("returns from About & code to the report it was opened from", async () => {
    render(<App />);
    fireEvent.click(await screen.findByText("Screenshare check (SS mode)"));
    fireEvent.click(screen.getByText("I agree — show the SS view"));
    expect(await screen.findByText("Found")).toBeTruthy();
    fireEvent.click(screen.getByText("About & code"));
    expect(await screen.findByText("About this program and its code")).toBeTruthy();
    // Opening it again from itself must not make it its own way back.
    fireEvent.click(screen.getByText("About & code"));
    fireEvent.click(screen.getByText("Back"));
    expect(await screen.findByText("Found")).toBeTruthy();
    expect(screen.getByText(/^Hidden in SS mode:/)).toBeTruthy();
    expect(screen.queryByText("You may refuse.")).toBeNull();
    expect(screen.queryByText("What do you want to do?")).toBeNull();
  });

  it("says a refused copy and leaves the text to select", async () => {
    stubClipboard("refused");
    render(<App />);
    fireEvent.click(await screen.findByText("About & code"));
    await screen.findByText(REPOSITORY);
    await act(async () => {
      fireEvent.click(screen.getAllByText("Copy link")[0] as HTMLElement);
    });
    expect(screen.getByText("Could not copy — select the text instead")).toBeTruthy();
  });
});
