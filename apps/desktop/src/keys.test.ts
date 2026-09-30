// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { describe, expect, it } from "vitest";
import { withKeys } from "./keys";

describe("withKeys", () => {
  it("gives two items that say the same two keys, in order", () => {
    const keyed = withKeys(["a", "b", "a"], (item) => item);
    expect(keyed).toEqual([
      ["a#0", "a"],
      ["b#0", "b"],
      ["a#1", "a"],
    ]);
    expect(new Set(keyed.map(([key]) => key)).size).toBe(3);
  });
});
