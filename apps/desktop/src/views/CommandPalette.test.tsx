// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// The palette reads the report's own evidence rows; these tests fix its keyboard contract and the
// combobox/listbox wiring.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

const VIEW = snapshot("secure_boot_off_self_view");
const SECOND = VIEW.evidence[1];
if (VIEW.evidence.length < 2 || !SECOND) throw new Error("the snapshot needs two evidence rows");

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
});

async function openPalette() {
  await screen.findByRole("button", { name: "Detailed Report" });
  fireEvent.keyDown(document, { key: "k", ctrlKey: true });
  const dialog = await screen.findByRole("dialog", { name: "Jump to evidence" });
  const input = within(dialog).getByRole("combobox", { name: "Search evidence" });
  await waitFor(() => expect(document.activeElement).toBe(input));
  return { dialog, input };
}

describe("Command palette", () => {
  it("opens with Ctrl K and closes with Esc, returning focus", async () => {
    render(<Report mode="self" onBack={vi.fn()} />);
    const before = await screen.findByRole("button", { name: "Detailed Report" });
    before.focus();
    const { input } = await openPalette();
    fireEvent.keyDown(input, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(before));
  });

  it("filters the options by the typed text", async () => {
    render(<Report mode="self" onBack={vi.fn()} />);
    const { dialog, input } = await openPalette();
    expect(within(dialog).getAllByRole("option")).toHaveLength(8);
    fireEvent.change(input, { target: { value: SECOND.rule_id } });
    await waitFor(() => {
      const options = within(dialog).getAllByRole("option");
      expect(options).toHaveLength(1);
      expect(options[0]?.textContent).toContain(SECOND.rule_id);
    });
  });

  it("picks the next option with ArrowDown and Enter, then focuses the report list", async () => {
    const { container } = render(<Report mode="self" onBack={vi.fn()} />);
    const { dialog, input } = await openPalette();
    fireEvent.keyDown(input, { key: "ArrowDown" });
    await waitFor(() =>
      expect(within(dialog).getAllByRole("option")[1]?.getAttribute("aria-selected")).toBe("true"),
    );
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const search = screen.getByRole("searchbox", { name: "Search checks" });
    expect((search as HTMLInputElement).value).toBe(SECOND.rule_id);
    expect(container.querySelector<HTMLElement>(".view-tech-wrap")?.style.display).toBe("block");
    await waitFor(() => expect(document.activeElement?.tagName).toBe("H3"));
  });

  it("wires the combobox to the listbox and announces the result count", async () => {
    render(<Report mode="self" onBack={vi.fn()} />);
    const { dialog, input } = await openPalette();
    const listbox = within(dialog).getByRole("listbox", { name: "Matching evidence" });
    const options = within(dialog).getAllByRole("option");
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(input.getAttribute("aria-expanded")).toBe("true");
    expect(input.getAttribute("aria-controls")).toBe(listbox.id);
    expect(input.getAttribute("aria-activedescendant")).toBe(options[0]?.id);
    expect(options.every((option) => option.id.length > 0)).toBe(true);
    expect(options[0]?.getAttribute("aria-selected")).toBe("true");
    expect(dialog.querySelector('[aria-live="polite"]')?.textContent).toBe(
      `${VIEW.evidence.length} matching check(s)`,
    );
  });
});
