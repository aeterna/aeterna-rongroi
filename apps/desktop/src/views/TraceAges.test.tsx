// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// ADR 0090 section 5: the antivirus products Windows lists, each with its state and what was read
// of its file; a list with no product; and a list that could not be read.

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import i18n, { initI18n } from "../i18n";
import type { CrossSourceStatement } from "../types";
import { CrossSource } from "./TraceAges";

type Antivirus = Extract<CrossSourceStatement, { kind: "antivirus" }>;

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
});

afterEach(() => {
  cleanup();
});

describe("CrossSource's antivirus statement", () => {
  const cases: {
    name: string;
    statement: Antivirus;
    expected: (string | RegExp)[];
    absent: string[];
  }[] = [
    {
      name: "products",
      statement: {
        kind: "antivirus",
        products: [
          {
            display_name: "Antivirus Microsoft Defender",
            state: "on",
            signature: "valid",
            signer: "Microsoft Windows",
            file_unread: "budget_spent",
          },
        ],
      },
      expected: [
        "Antivirus products Windows Security Center lists",
        /Antivirus Microsoft Defender: reports itself on/,
        "Embedded signature: verifies",
        "Signer: Microsoft Windows",
        "its file was not read (budget_spent)",
        "A product listed here is what is registered with Windows, not proof that it scans.",
      ],
      absent: ["Security Center lists no antivirus product.", "The list could not be read:"],
    },
    {
      name: "none",
      statement: { kind: "antivirus", products: [] },
      expected: [
        "Security Center lists no antivirus product.",
        "A product listed here is what is registered with Windows, not proof that it scans.",
      ],
      absent: ["The list could not be read:"],
    },
    {
      name: "not read",
      statement: { kind: "antivirus", products: [], not_read: "read_failed" },
      expected: [
        "not read — this could not be read",
        "A product listed here is what is registered with Windows, not proof that it scans.",
      ],
      absent: ["Security Center lists no antivirus product."],
    },
  ];

  it.each(cases)("shows the antivirus statement: $name", ({ statement, expected, absent }) => {
    render(<CrossSource statements={[statement]} />);
    for (const text of expected) {
      expect(screen.getByText(text)).toBeTruthy();
    }
    for (const text of absent) {
      expect(screen.queryByText(text)).toBeNull();
    }
  });
});
