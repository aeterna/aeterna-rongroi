// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// ADR 0045: the telemetry line is a readout of the evidence, not a verdict. Its animation is
// decoration, so the full line must be in the DOM from the first render of an open row.

import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import i18n, { initI18n } from "../i18n";
import type { Evidence } from "../types";
import { EvidenceRow } from "./EvidenceRow";

const RULE_ID = "3b9e1c2a-5d7f-4e8a-9c1b-2f6d8a0e4b71";
const LINE = `rule ${RULE_ID} - collector evtx - state found`;

const FOUND: Evidence = {
  rule_id: RULE_ID,
  collector: "evtx",
  strength: "tamper",
  state: "found",
  observations: [{ collector: "evtx", fields: { channel: "System" } }],
};

const originalMatchMedia = Object.getOwnPropertyDescriptor(window, "matchMedia");

function renderFoundRow() {
  return render(
    <EvidenceRow
      item={FOUND}
      text={undefined}
      fileBase={null}
      treeBase={null}
      linksKnown={true}
      official={false}
      technicalAll={false}
    />,
  );
}

function telemetryText(selector: string): string | null {
  return document.querySelector(selector)?.textContent ?? null;
}

function typedText(): string | null {
  return telemetryText(".row-telemetry-typed");
}

interface MatchMediaStub {
  matches: boolean;
  addEventListener: ReturnType<typeof vi.fn>;
  removeEventListener: ReturnType<typeof vi.fn>;
}

function installMatchMedia(
  matches: boolean,
  addEventListener = vi.fn(),
  removeEventListener = vi.fn(),
): MatchMediaStub {
  const media = {
    matches,
    media: "(prefers-reduced-motion: reduce)",
    onchange: null,
    addEventListener,
    removeEventListener,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  };
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: vi.fn(() => media),
  });
  return { matches, addEventListener, removeEventListener };
}

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
  vi.useFakeTimers();
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

describe("telemetry line on an open evidence row", () => {
  it("has the whole line in the DOM on the first render", () => {
    renderFoundRow();

    const whole = document.querySelector(".row-telemetry-hidden");
    expect(whole?.textContent).toBe(LINE);
    expect(whole?.getAttribute("aria-hidden")).not.toBe("true");

    const typed = document.querySelector(".row-telemetry-typed");
    expect(typed?.getAttribute("aria-hidden")).toBe("true");
  });

  it("types the visible copy one character at a time", () => {
    renderFoundRow();
    expect(typedText()).toBe("");

    act(() => {
      vi.advanceTimersByTime(12);
    });
    expect(typedText()).toBe(LINE.slice(0, 1));

    act(() => {
      vi.advanceTimersByTime(36);
    });
    expect(typedText()).toBe(LINE.slice(0, 4));

    act(() => {
      vi.advanceTimersByTime(LINE.length * 12);
    });
    expect(typedText()).toBe(LINE);
  });

  it("shows the whole line at once when reduced motion is requested", () => {
    const setIntervalSpy = vi.spyOn(window, "setInterval");
    installMatchMedia(true);
    renderFoundRow();

    expect(typedText()).toBe(LINE);
    expect(setIntervalSpy).not.toHaveBeenCalled();
  });

  it("clears the typing timer on unmount", () => {
    const setIntervalSpy = vi.spyOn(window, "setInterval");
    const clearIntervalSpy = vi.spyOn(window, "clearInterval");
    const { unmount } = renderFoundRow();
    expect(typedText()).toBe("");

    const typingTimers = setIntervalSpy.mock.results.map((result) => result.value);
    expect(typingTimers).toHaveLength(1);

    act(() => {
      vi.advanceTimersByTime(24);
    });
    expect(typedText()).toBe(LINE.slice(0, 2));

    clearIntervalSpy.mockClear();
    unmount();
    expect(clearIntervalSpy).toHaveBeenCalledWith(typingTimers[0]);
  });

  it("removes the reduced-motion change listener on unmount", () => {
    const media = installMatchMedia(false);
    const { unmount } = renderFoundRow();

    expect(media.addEventListener).toHaveBeenCalledWith("change", expect.any(Function));
    unmount();
    expect(media.removeEventListener).toHaveBeenCalledWith("change", expect.any(Function));
  });
});
