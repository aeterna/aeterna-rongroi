// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// H8: the frosted tool-panel look is pure CSS, so it is checked by reading the sheet as text.
// The sticky header keeps the only backdrop-filter — a weak PC must not pay for a second blur — and
// the translucent panels get their light inner edge from the --panel-edge token instead.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const CSS = readFileSync(resolve(__dirname, "styles.css"), "utf8");

describe("styles.css frosted tool panels", () => {
  it("keeps the sticky header as the only backdrop-filter", () => {
    expect(CSS.match(/backdrop-filter/g) ?? []).toHaveLength(1);
  });

  it("defines the --panel-edge token as a light inner edge", () => {
    expect(CSS).toMatch(/--panel-edge:\s*inset 0 1px 0 #ffffffcc,\s*inset 0 0 0 1px #ffffff66;/);
  });

  it("uses the inner edge with the soft shadow on at least three rules", () => {
    const uses = CSS.match(/box-shadow:\s*var\(--panel-edge\),\s*var\(--shadow\);/g) ?? [];
    expect(uses.length).toBeGreaterThanOrEqual(3);
  });
});
