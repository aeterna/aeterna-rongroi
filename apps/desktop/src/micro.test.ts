// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// E12: the micro-interactions are pure CSS, so they are checked by reading the sheets as text.
// jsdom does not evaluate cascades or media queries, so only these assertions can see that none of
// the decoration is reachable under reduced motion.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Vitest runs with apps/desktop as the working directory.
const SRC = resolve(process.cwd(), "src");

/** Properties whose change can move, fade or glow; nothing else may animate. */
const ANIMATED_PROPERTIES = [
  "animation",
  "box-shadow",
  "opacity",
  "rotate",
  "scale",
  "transform",
  "transition",
  "translate",
  "will-change",
];

interface Declaration {
  property: string;
  value: string;
  /** Whether the declaration sits inside `@media (prefers-reduced-motion: no-preference)`. */
  insideMotionQuery: boolean;
}

/**
 * Reads every property declaration of one style sheet with the motion context it sits in. The
 * repo's CSS is plain (rules, comments, media queries, no strings or data URIs), so a small walk
 * that keeps a stack of block depths is enough; unbalanced braces throw instead of passing.
 */
function animatedDeclarations(sheet: string): Declaration[] {
  const text = sheet.replace(/\r\n/g, "\n").replace(/\/\*[\s\S]*?\*\//g, " ");
  const result: Declaration[] = [];
  const parentStates: boolean[] = [];
  let depth = 0;
  let inside = false;
  // Whether the text since the last `;`, `{` or `}` is inside a block body; a rule prelude after a
  // body is not, so pseudo-classes such as `button:active` are never read as declarations.
  let inBody = false;
  let segmentStart = 0;

  const collect = (segment: string) => {
    const atColon = /^\s*([-A-Za-z]+)\s*:/.exec(segment);
    const property = atColon?.[1];
    if (!property || !ANIMATED_PROPERTIES.includes(property)) return;
    const value = segment.slice(atColon[0]?.length ?? segment.length).trim();
    if (value === "none") return; // clears an animation instead of running one
    result.push({ property, value, insideMotionQuery: inside });
  };

  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (char === "{") {
      const prelude = text.slice(segmentStart, index);
      parentStates.push(inside);
      if (/@media[^{}]*prefers-reduced-motion:\s*no-preference/.test(prelude)) {
        inside = true;
      } else if (/@media[^{}]*prefers-reduced-motion:\s*reduce/.test(prelude)) {
        inside = false;
      }
      depth += 1;
      inBody = true;
      segmentStart = index + 1;
    } else if (char === "}") {
      if (inBody) collect(text.slice(segmentStart, index));
      depth -= 1;
      inside = parentStates.pop() ?? false;
      inBody = depth > 0;
      segmentStart = index + 1;
    } else if (char === ";" && inBody) {
      collect(text.slice(segmentStart, index));
      segmentStart = index + 1;
    }
  }
  if (depth !== 0) throw new Error("micro.css has unbalanced braces");
  return result;
}

describe("micro.css (E12 micro-interactions)", () => {
  it("is imported from main.tsx after the main style sheet", () => {
    const main = readFileSync(resolve(SRC, "main.tsx"), "utf8");
    const micro = main.indexOf("import \"./micro.css\";");
    const styles = main.indexOf("import \"./styles.css\";");
    expect(micro).toBeGreaterThan(-1);
    // Both sheets style plain `button`; the press transition wins the cascade only if micro.css
    // loads after styles.css.
    expect(micro).toBeGreaterThan(styles);
  });

  it("keeps every animated declaration behind the no-preference motion query", () => {
    const declarations = animatedDeclarations(readFileSync(resolve(SRC, "micro.css"), "utf8"));
    // The sheet must animate something, so an empty or gutted file cannot pass by accident.
    expect(declarations.length).toBeGreaterThan(0);
    expect(declarations.some(({ property }) => property === "transition")).toBe(true);
    expect(declarations.some(({ property }) => property === "transform")).toBe(true);
    const outside = declarations.filter(({ insideMotionQuery }) => !insideMotionQuery);
    expect(outside).toEqual([]);
  });

  it("presses buttons for 90 ms and bounces the tally back on its own 140 ms spring", () => {
    const css = readFileSync(resolve(SRC, "micro.css"), "utf8");
    expect(css).toMatch(/@media[^{]*prefers-reduced-motion:\s*no-preference/);
    expect(css).toMatch(/button:active:not\(:disabled\)\s*\{\s*transform:\s*scale\(0\.97\);/);
    expect(css).toMatch(/transform\s+90ms\s+ease/);
    expect(css).toMatch(/\.tally-item\s*\{[^{}]*transform\s+140ms\s+cubic-bezier/);
  });

  it("adds a glow ring on :focus-visible and never touches the outline", () => {
    const css = readFileSync(resolve(SRC, "micro.css"), "utf8");
    expect(css).toMatch(/:focus-visible\s*\{/);
    expect(css).toMatch(/0 0 0 3px rgba\(8, 105, 176, 0\.35\)/);
    // styles.css owns the focus outline; this sheet must not declare one of its own, in shorthand
    // or longhand, so it cannot remove it from focused elements.
    expect(css).not.toMatch(/outline\s*:/);
  });

  it("carries the SPDX header and no zero-width or bidi control characters", () => {
    const css = readFileSync(resolve(SRC, "micro.css"), "utf8");
    const header = "/* SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors */";
    expect(css.startsWith(header)).toBe(true);
    const control = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069]/;
    expect(control.test(css)).toBe(false);
    expect(control.test(readFileSync(resolve(SRC, "main.tsx"), "utf8"))).toBe(false);
  });
});
