// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useEffect, useState } from "react";

/** Digits every rolling strip holds, from 0 to 9. */
const DIGITS = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];

/** Reads the user's motion preference; a missing matchMedia (tests, jsdom) counts as no request. */
function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Shows a count as digits that roll once on mount. The real number is in the DOM from the first
 * render as visually hidden text; the strips are decoration and hidden from assistive technology.
 */
export function Odometer({ value }: { value: number }) {
  const digits = String(value).split("");
  const places = digits.map((digit, index) => ({
    digit,
    key: `place-${digits.length - index}`,
    delay: `${index * 80}ms`,
  }));
  const [started, setStarted] = useState(prefersReducedMotion);

  useEffect(() => {
    if (started) return undefined;
    const frame = window.requestAnimationFrame(() => setStarted(true));
    return () => window.cancelAnimationFrame(frame);
  }, [started]);

  return (
    <span className="odometer">
      <span className="odometer-value">{digits.join("")}</span>
      <span className="odometer-strips" aria-hidden="true">
        {places.map(({ digit, key, delay }) => (
          <span className="odometer-digit" key={key}>
            <span
              className="odometer-strip"
              style={{
                transform: `translateY(${started ? -Number(digit) : 0}em)`,
                transitionDelay: delay,
              }}
            >
              {DIGITS.map((row) => (
                <span key={row}>{row}</span>
              ))}
            </span>
          </span>
        ))}
      </span>
    </span>
  );
}
