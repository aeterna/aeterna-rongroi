// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { afterEach, describe, expect, it, vi } from "vitest";
import { changeScreen } from "./App.transition";

type StartViewTransition = (update: () => void) => unknown;

const originalStartViewTransition = Object.getOwnPropertyDescriptor(
  document,
  "startViewTransition",
);
const originalMatchMedia = Object.getOwnPropertyDescriptor(window, "matchMedia");

function stubStartViewTransition(start: StartViewTransition): void {
  Object.defineProperty(document, "startViewTransition", {
    configurable: true,
    value: start,
  });
}

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

afterEach(() => {
  if (originalStartViewTransition) {
    Object.defineProperty(document, "startViewTransition", originalStartViewTransition);
  } else {
    Reflect.deleteProperty(document, "startViewTransition");
  }
  if (originalMatchMedia) {
    Object.defineProperty(window, "matchMedia", originalMatchMedia);
  } else {
    Reflect.deleteProperty(window, "matchMedia");
  }
});

describe("changeScreen", () => {
  it("runs the update synchronously without the View Transitions API", () => {
    stubReducedMotion(false);
    Object.defineProperty(document, "startViewTransition", {
      configurable: true,
      value: undefined,
    });
    const update = vi.fn();

    changeScreen(update);

    expect(update).toHaveBeenCalledTimes(1);
  });

  it("hands the update to startViewTransition when the API is available", () => {
    stubReducedMotion(false);
    let callback: (() => void) | undefined;
    const start = vi.fn((next: () => void) => {
      callback = next;
    });
    stubStartViewTransition(start);
    const update = vi.fn();

    changeScreen(update);

    expect(start).toHaveBeenCalledTimes(1);
    expect(callback).toBeTypeOf("function");
    callback?.();
    expect(update).toHaveBeenCalledTimes(1);
  });

  it("does not use a view transition when reduced motion is matched", () => {
    stubReducedMotion(true);
    const start = vi.fn();
    stubStartViewTransition(start);
    const update = vi.fn();

    changeScreen(update);

    expect(start).not.toHaveBeenCalled();
    expect(update).toHaveBeenCalledTimes(1);
  });
});
