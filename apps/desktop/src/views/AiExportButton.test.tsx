// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// ADR 0084 decision 2: the AI export asks for causes, not a verdict. The questions and the opening
// sentence come from the locale files, and the prompt ends by saying the report is evidence.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import i18n, { initI18n } from "../i18n";
import type { ReportView } from "../types";
import { AiExportButton } from "./AiExportButton";

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/rongroi-collectors/tests/snapshots");

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

const VIEW = snapshot("secure_boot_off_self_view");
const EN_QUESTIONS =
  "1. For each observation, what ordinary causes produce it, and what other causes could? 2. What do the unmeasured checks leave unknown? 3. A three-line summary. Do not conclude that this PC is clean or that it was used to cheat: the report is evidence, not a verdict.";

// Carried from App.test.tsx: the real descriptor is restored afterwards, so a fake clipboard does not
// leak into the next test file.
const originalClipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard");
let clipboardWrites: string[] = [];

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  clipboardWrites = [];
  await i18n.changeLanguage("en");
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: (text: string) => {
        clipboardWrites.push(text);
        return Promise.resolve();
      },
    },
  });
});

afterEach(() => {
  cleanup();
  if (originalClipboardDescriptor) {
    Object.defineProperty(navigator, "clipboard", originalClipboardDescriptor);
  } else {
    (navigator as { clipboard?: unknown }).clipboard = undefined;
  }
});

/** Clicks the export button and returns the prompt it copied. */
function copyPrompt(label: string): string {
  render(<AiExportButton view={VIEW} header={VIEW.header} texts={{}} />);
  fireEvent.click(screen.getByRole("button", { name: label }));
  const copied = clipboardWrites[0];
  if (copied === undefined) {
    throw new Error("the export copied nothing");
  }
  return copied;
}

describe("AI export prompt in English", () => {
  it("asks for the causes and says the report is evidence, not a verdict", () => {
    const prompt = copyPrompt("Copy for AI Analysis");
    expect(prompt).toContain(EN_QUESTIONS);
    expect(prompt).toContain("evidence, not a verdict");
  });

  it("does not ask whether the PC is benign or ordinary", () => {
    const prompt = copyPrompt("Copy for AI Analysis");
    for (const word of ["benign", "Benign", "ordinary user patterns", "บุคคลทั่วไป"]) {
      expect(prompt).not.toContain(word);
    }
  });
});

describe("AI export prompt in Thai", () => {
  it("says the report is evidence, not a verdict", async () => {
    await i18n.changeLanguage("th");
    const prompt = copyPrompt("คัดลอกส่งให้ AI สรุปวิเคราะห์");
    expect(prompt).toContain("ไม่ใช่คำตัดสิน");
  });

  it("does not repeat the continuous-history claim or ask whether the PC is benign", async () => {
    await i18n.changeLanguage("th");
    const prompt = copyPrompt("คัดลอกส่งให้ AI สรุปวิเคราะห์");
    const forbidden = [
      "ความต่อเนื่อง",
      "benign",
      "Benign",
      "ordinary user patterns",
      "บุคคลทั่วไป",
    ];
    for (const word of forbidden) {
      expect(prompt).not.toContain(word);
    }
  });
});
