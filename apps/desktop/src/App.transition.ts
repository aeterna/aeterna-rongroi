// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { flushSync } from "react-dom";

/** The View Transitions API as much of it as this helper needs, so an older lib build still compiles. */
type ViewTransitionDocument = Document & {
  startViewTransition?: (update: () => void) => unknown;
};

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

/**
 * Changes the screen through a view transition when the browser offers one and the reader has not
 * asked for reduced motion. Without the API every screen still changes exactly as before.
 */
export function changeScreen(update: () => void): void {
  const target = document as ViewTransitionDocument;
  if (typeof target.startViewTransition !== "function" || prefersReducedMotion()) {
    update();
    return;
  }
  target.startViewTransition(() => flushSync(update));
}
