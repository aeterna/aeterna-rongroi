// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// H1: the large digest decodes once on mount as decoration. The real value is in the DOM from the
// first render, reduced motion shows it at once, and the timer is cleared on unmount.

import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import i18n, { initI18n } from "../i18n";
import { SavedRecordBox } from "./SavedRecordBox";

const DIGEST = "3f9a1c2e7b4d5a60918273645f0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6";
const SHOWN = "3f9a 1c2e 7b4d 5a60";
const SAVED = {
  digest: DIGEST,
  size: 163_000,
  case_code: null,
  visual_hash: "5777137e45484779",
};

const originalMatchMedia = Object.getOwnPropertyDescriptor(window, "matchMedia");

/** Replaces `window.matchMedia` with one that answers the reduced-motion query as `reduced`. */
function stubReducedMotion(reduced: boolean): void {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: (query: string) =>
      ({
        matches: query === "(prefers-reduced-motion: reduce)" && reduced,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }) as unknown as MediaQueryList,
  });
}

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
  if (originalMatchMedia) {
    Object.defineProperty(window, "matchMedia", originalMatchMedia);
  } else {
    Reflect.deleteProperty(window, "matchMedia");
  }
});

describe("SavedRecordBox digest decode", () => {
  it("keeps the final digest readable and the frame decorative from the first render", () => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0);
    const { container } = render(<SavedRecordBox saved={SAVED} />);
    const digest = container.querySelector(".digest");
    const hidden = container.querySelector(".digest-final");
    const visible = container.querySelector(".digest-frame");
    expect(digest?.getAttribute("aria-label")).toBeNull();
    expect(hidden?.textContent).toBe(SHOWN);
    expect(hidden?.getAttribute("aria-hidden")).not.toBe("true");
    expect(visible?.getAttribute("aria-hidden")).toBe("true");
    expect(visible?.textContent).toBe(SHOWN);
    expect(container.querySelector("code")?.textContent).toBe(DIGEST);

    act(() => {
      vi.advanceTimersByTime(80);
    });
    const frameText = visible?.textContent ?? "";
    expect(hidden?.textContent).toBe(SHOWN);
    expect(hidden?.getAttribute("aria-hidden")).not.toBe("true");
    expect(frameText).toMatch(/^[0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4}$/);
    expect(frameText).not.toBe(SHOWN);
    // The strong also carries the hidden real value, so its text is not the decorative frame alone.
    expect(digest?.textContent).not.toBe(frameText);
    expect(container.querySelector("code")?.textContent).toBe(DIGEST);

    act(() => {
      vi.advanceTimersByTime(920);
    });
    expect(visible?.textContent).toBe(SHOWN);
    expect(hidden?.textContent).toBe(SHOWN);
    expect(hidden?.getAttribute("aria-hidden")).not.toBe("true");
  });

  it("shows the final digest at once and schedules no decode under reduced motion", () => {
    stubReducedMotion(true);
    const setIntervalSpy = vi.spyOn(window, "setInterval");

    const { container } = render(<SavedRecordBox saved={SAVED} />);
    const digest = container.querySelector(".digest");
    const hidden = container.querySelector(".digest-final");
    const visible = container.querySelector(".digest-frame");
    expect(digest?.getAttribute("aria-label")).toBeNull();
    expect(hidden?.textContent).toBe(SHOWN);
    expect(hidden?.getAttribute("aria-hidden")).not.toBe("true");
    expect(visible?.textContent).toBe(SHOWN);
    expect(visible?.getAttribute("aria-hidden")).toBe("true");
    expect(setIntervalSpy).not.toHaveBeenCalled();
  });

  it("does not restart the decode when the save state re-renders", () => {
    stubReducedMotion(false);
    vi.useFakeTimers();
    const setIntervalSpy = vi.spyOn(window, "setInterval");

    const { rerender } = render(<SavedRecordBox saved={SAVED} />);
    rerender(<SavedRecordBox saved={{ ...SAVED }} />);
    expect(setIntervalSpy).toHaveBeenCalledTimes(1);
  });

  it("clears the decode timer on unmount", () => {
    stubReducedMotion(false);
    vi.useFakeTimers();
    const setIntervalSpy = vi.spyOn(window, "setInterval");
    const clearIntervalSpy = vi.spyOn(window, "clearInterval");

    const { unmount } = render(<SavedRecordBox saved={SAVED} />);
    expect(setIntervalSpy).toHaveBeenCalledTimes(1);
    const timer = setIntervalSpy.mock.results[0]?.value;

    unmount();
    expect(clearIntervalSpy).toHaveBeenCalledWith(timer);
  });
});
