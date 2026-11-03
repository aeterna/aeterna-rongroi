// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// The reader's own motion switch: the attribute, the remembered choice, the reduced-motion answer,
// the React control and the stylesheet that makes the attribute stop animation.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { initMotion, motionReduced, setAnimationsOff, useAnimationsOff } from "./motion";

const KEY = "rongroi.motion";
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

function Probe() {
  return <output data-testid="probe">{useAnimationsOff() ? "off" : "on"}</output>;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  delete document.documentElement.dataset.motion;
  window.localStorage.clear();
  if (originalMatchMedia) {
    Object.defineProperty(window, "matchMedia", originalMatchMedia);
  } else {
    Reflect.deleteProperty(window, "matchMedia");
  }
});

describe("setAnimationsOff", () => {
  it("sets the attribute and remembers off, then removes it and remembers on", () => {
    setAnimationsOff(true);
    expect(document.documentElement.dataset.motion).toBe("off");
    expect(document.documentElement.hasAttribute("data-motion")).toBe(true);
    expect(window.localStorage.getItem(KEY)).toBe("off");

    setAnimationsOff(false);
    expect(document.documentElement.dataset.motion).toBeUndefined();
    expect(document.documentElement.hasAttribute("data-motion")).toBe(false);
    expect(window.localStorage.getItem(KEY)).toBe("on");
  });
});

describe("motionReduced", () => {
  it("reports reduced motion when the app switch is off, even without a platform preference", () => {
    document.documentElement.dataset.motion = "off";
    stubReducedMotion(false);

    expect(motionReduced()).toBe(true);
  });

  it("reports no reduced motion when the switch is unset and the platform does not ask for it", () => {
    stubReducedMotion(false);

    expect(motionReduced()).toBe(false);
  });

  it("reports reduced motion when the platform asks for it", () => {
    stubReducedMotion(true);

    expect(motionReduced()).toBe(true);
  });
});

describe("initMotion", () => {
  it("applies a stored off choice", () => {
    window.localStorage.setItem(KEY, "off");

    initMotion();

    expect(document.documentElement.dataset.motion).toBe("off");
  });

  it("leaves the attribute unset when nothing is stored", () => {
    initMotion();

    expect(document.documentElement.hasAttribute("data-motion")).toBe(false);
  });

  it("does not throw when storage cannot be read", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("storage is unavailable");
    });

    expect(() => initMotion()).not.toThrow();
    expect(document.documentElement.hasAttribute("data-motion")).toBe(false);
  });
});

describe("useAnimationsOff", () => {
  it("re-renders after setAnimationsOff(true)", () => {
    stubReducedMotion(false);
    render(<Probe />);
    expect(screen.getByTestId("probe").textContent).toBe("on");

    act(() => {
      setAnimationsOff(true);
    });

    expect(screen.getByTestId("probe").textContent).toBe("off");
  });
});

describe("motion-off.css", () => {
  it("targets the off attribute and stops animation", () => {
    const css = readFileSync(resolve(__dirname, "motion-off.css"), "utf8");

    expect(css).toContain('html[data-motion="off"]');
    expect(css).toContain("animation: none !important");
  });
});
