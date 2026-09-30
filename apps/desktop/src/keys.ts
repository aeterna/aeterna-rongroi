// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

/**
 * Each item with a React key made of what it says, and a count for the items that say the same.
 *
 * Two identical items are an honest part of a report: two copies of one program running are two
 * identical `process` observations (ADR 0010). A key made of the content alone would repeat.
 */
export function withKeys<T>(items: readonly T[], base: (item: T) => string): [string, T][] {
  const seen = new Map<string, number>();
  return items.map((item) => {
    const text = base(item);
    const count = seen.get(text) ?? 0;
    seen.set(text, count + 1);
    return [`${text}#${count}`, item];
  });
}
