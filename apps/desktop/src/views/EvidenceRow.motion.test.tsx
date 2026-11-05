// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// ADR 0045: the telemetry line is a readout of the evidence, not a verdict. Its animation is
// decoration, so the full line must be in the DOM from the first render of an open row.

import { act, cleanup, fireEvent, render } from "@testing-library/react";
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

const NOT_FOUND: Evidence = {
  rule_id: RULE_ID,
  collector: "evtx",
  strength: "tamper",
  state: "not_found",
  retention: "the look-back the rule states",
};

let clipboardWrites: string[] = [];

function stubClipboard(result: "ok" | "refused") {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: (text: string) => {
        if (result === "refused") {
          return Promise.reject(new Error("refused"));
        }
        clipboardWrites.push(text);
        return Promise.resolve();
      },
    },
  });
}

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

function renderNotFoundRow() {
  return render(
    <EvidenceRow
      item={NOT_FOUND}
      text={undefined}
      fileBase={null}
      treeBase={null}
      linksKnown={true}
      official={false}
      technicalAll={false}
    />,
  );
}

/** A found row with its technical layer shown, so the JSON copy button is present. */
function renderTechnicalRow() {
  const rendered = renderFoundRow();
  const disclosure = rendered.container.querySelector(".disclosure");
  act(() => {
    fireEvent.click(disclosure as HTMLElement);
  });
  const copyButton = rendered.getByRole("button", { name: "Copy raw JSON" });
  return { ...rendered, copyButton: copyButton as HTMLButtonElement };
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
  clipboardWrites = [];
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  Reflect.deleteProperty(navigator, "clipboard");
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

describe("the row body fold", () => {
  it("mounts a fresh body at its closed start and unfolds it on the next frame", () => {
    const frames: FrameRequestCallback[] = [];
    vi.spyOn(window, "requestAnimationFrame").mockImplementation((cb) => {
      frames.push(cb);
      return frames.length;
    });
    const { container } = renderNotFoundRow();
    const head = container.querySelector(".row-head") as HTMLElement;

    act(() => {
      fireEvent.click(head);
    });
    const fold = container.querySelector(".row-fold") as HTMLElement;
    expect(fold).not.toBeNull();
    // The body is at the fold's closed height; its content is in the DOM from here on.
    expect(fold.getAttribute("data-open")).toBe("false");
    expect(fold.querySelector(".row-body")).not.toBeNull();
    expect(fold.hasAttribute("inert")).toBe(true);
    // aria-expanded flips at once, exactly as before.
    expect(head.getAttribute("aria-expanded")).toBe("true");

    act(() => {
      for (const frame of frames) {
        frame(performance.now());
      }
    });
    expect(fold.getAttribute("data-open")).toBe("true");
    expect(fold.hasAttribute("inert")).toBe(false);
    // Open, the body is in the accessibility tree and never display:none: it stays a real grid
    // row for the fold to animate.
  });

  it("keeps the body in the DOM during and after a collapse instead of display none", () => {
    const { container } = renderFoundRow();
    const head = container.querySelector(".row-head") as HTMLElement;
    const fold = container.querySelector(".row-fold") as HTMLElement;
    expect(fold).not.toBeNull();
    // A found row starts unfolded, so its body is not inert before any click.
    expect(fold.getAttribute("data-open")).toBe("true");
    expect(fold.hasAttribute("inert")).toBe(false);

    act(() => {
      fireEvent.click(head);
    });
    // The collapse animates: the body stays mounted, and only its fold turns closed — closed
    // already means inert, from the first frame of the collapse and not just after the timer.
    expect(fold.querySelector(".row-body")).not.toBeNull();
    expect(fold.getAttribute("data-open")).toBe("false");
    expect(fold.hasAttribute("inert")).toBe(true);

    act(() => {
      vi.advanceTimersByTime(200);
    });
    // After the transition the fold is out of the accessibility tree via visibility and inert,
    // while it stays in the document rather than being taken out with display.
    expect(fold.querySelector(".row-body")).not.toBeNull();
    expect(fold.hasAttribute("inert")).toBe(true);
  });

  it("hands keyboard focus to the head when the body collapses while focus is inside it", () => {
    const { container } = renderFoundRow();
    const head = container.querySelector(".row-head") as HTMLElement;
    const disclosure = container.querySelector(".disclosure") as HTMLElement;

    act(() => {
      disclosure.focus();
    });
    act(() => {
      fireEvent.click(head);
    });
    expect(document.activeElement).toBe(head);

    act(() => {
      vi.advanceTimersByTime(200);
    });
    // The body is inert now; focus was never left behind in it.
    expect(document.activeElement).toBe(head);
  });

  it("opens a body at its final state at once under reduced motion", () => {
    const frame = vi.spyOn(window, "requestAnimationFrame").mockReturnValue(1);
    installMatchMedia(true);
    const { container } = renderNotFoundRow();
    const head = container.querySelector(".row-head") as HTMLElement;

    act(() => {
      fireEvent.click(head);
    });
    const fold = container.querySelector(".row-fold") as HTMLElement;
    expect(fold).not.toBeNull();
    expect(fold.getAttribute("data-open")).toBe("true");
    expect(fold.hasAttribute("inert")).toBe(false);
    expect(frame).not.toHaveBeenCalled();
  });

  it("collapses a body at once under reduced motion", () => {
    installMatchMedia(true);
    const { container } = renderFoundRow();
    const head = container.querySelector(".row-head") as HTMLElement;
    const fold = container.querySelector(".row-fold") as HTMLElement;
    expect(fold).not.toBeNull();

    act(() => {
      fireEvent.click(head);
    });
    expect(fold.getAttribute("data-open")).toBe("false");
    expect(fold.hasAttribute("inert")).toBe(true);
  });
});

describe("the JSON copy button", () => {
  it("marks the copy check as decoration and keeps the label words for assistive technology", async () => {
    stubClipboard("ok");
    const { container, copyButton } = renderTechnicalRow();

    await act(async () => {
      fireEvent.click(copyButton);
    });
    expect(clipboardWrites.length).toBe(1);
    // The visible label keeps its words; the check beside them is decoration.
    expect(copyButton.textContent).toBe("Copied");
    expect(copyButton.getAttribute("aria-label")).toBe("Copy raw JSON");
    const check = container.querySelector(".copy-json-check");
    expect(check?.getAttribute("aria-hidden")).toBe("true");
  });

  it("announces the copy in a polite live region that is outside the button", async () => {
    stubClipboard("ok");
    const { container, copyButton } = renderTechnicalRow();

    await act(async () => {
      fireEvent.click(copyButton);
    });
    const live = container.querySelector('[aria-live="polite"]');
    expect(live?.textContent).toBe("Copied");
    expect(live?.classList.contains("visually-hidden")).toBe(true);
    expect(copyButton.contains(live as Node)).toBe(false);
  });

  it("goes back to the plain label, and empties the live region, 1.5 s after a copy", async () => {
    stubClipboard("ok");
    const { copyButton } = renderTechnicalRow();

    await act(async () => {
      fireEvent.click(copyButton);
    });
    expect(copyButton.textContent).toBe("Copied");

    act(() => {
      vi.advanceTimersByTime(1499);
    });
    expect(copyButton.textContent).toBe("Copied");

    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(copyButton.textContent).toBe("Copy raw JSON");
    expect(document.querySelector('[aria-live="polite"]')?.textContent).toBe("");
  });

  it("clears the revert timer when the row unmounts", async () => {
    stubClipboard("ok");
    const { unmount, copyButton } = renderTechnicalRow();

    await act(async () => {
      fireEvent.click(copyButton);
    });
    // Let the telemetry typing finish so the revert timer is the only one left.
    act(() => {
      vi.advanceTimersByTime(1400);
    });
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});

// The row carries a copy button (the raw JSON of a technical observation), so the copied state
// above applies; there is no copy-free row variant to skip it for.
