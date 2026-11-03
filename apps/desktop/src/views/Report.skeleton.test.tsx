// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// H9: while the report view is still on its way, the page shows its own shape instead of nothing.
// The status line is real text in the DOM and says only that the report is loading; the scan has
// already finished, so no wording here may bring it back.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
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

/** A `report_view` answer the test settles only when it wants the report to appear. */
function deferredView() {
  let settleView: (view: ReportView) => void = () => {};
  const promise = new Promise<ReportView>((settle) => {
    settleView = settle;
  });
  return { promise, settle: settleView };
}

let pendingView: ReturnType<typeof deferredView>;

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
  pendingView = deferredView();
  mockIPC((cmd) => {
    switch (cmd) {
      case "report_view":
        return pendingView.promise;
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
});

describe("Report loading skeleton (H9)", () => {
  it("shows the skeleton and its loading status until the report view arrives", async () => {
    render(<Report mode="self" onBack={() => {}} />);

    const skeleton = document.querySelector<HTMLElement>(".report-skeleton");
    expect(skeleton).not.toBeNull();
    if (!skeleton) throw new Error("no report skeleton while the view is pending");
    expect(skeleton.getAttribute("aria-busy")).toBe("true");

    const status = screen.getByRole("status");
    expect(status.textContent).toBe("Loading the report");
    expect(status.className).toContain("visually-hidden");
    // The placeholder blocks are decoration: hidden from assistive technology and empty.
    const blocks = skeleton.querySelectorAll('[aria-hidden="true"]');
    expect(blocks).toHaveLength(3);
    for (const block of blocks) {
      expect(block.textContent).toBe("");
    }
    // The scan is over; this page is only loading its result.
    expect(skeleton.textContent ?? "").not.toMatch(/scan/i);

    await act(async () => {
      pendingView.settle(VIEW);
      await pendingView.promise;
    });

    expect(document.querySelector(".report-skeleton")).toBeNull();
    await screen.findByText("Overview Summary");
  });
});
