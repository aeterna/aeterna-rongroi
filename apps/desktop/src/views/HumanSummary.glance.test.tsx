// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { initI18n } from "../i18n";
import type { ReportView } from "../types";
import { HumanSummary } from "./HumanSummary";
import { useGlanceFx } from "./HumanSummary.glance";

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/rongroi-collectors/tests/snapshots");
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";
const originalMatchMedia = window.matchMedia;

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

/** Makes the card report a real box so the pointer maths can run in jsdom. */
function stubBoundingRect() {
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockReturnValue({
    x: 0,
    y: 0,
    top: 0,
    left: 0,
    right: 200,
    bottom: 100,
    width: 200,
    height: 100,
    toJSON: () => ({}),
  });
}

/** Records rAF callbacks so a test can run exactly the frame it means to. */
function queueFrames() {
  const pending: FrameRequestCallback[] = [];
  vi.spyOn(window, "requestAnimationFrame").mockImplementation((callback) => {
    pending.push(callback);
    return pending.length;
  });
  vi.spyOn(window, "cancelAnimationFrame").mockImplementation(() => {});
  return {
    pending,
    flush() {
      for (const callback of pending.splice(0)) callback(0);
    },
  };
}

type MotionListener = (event: MediaQueryListEvent) => void;

/** Stubs the motion query and exposes its change event, so re-checking is testable. */
function stubMatchMedia(matches: boolean) {
  const listeners = new Set<MotionListener>();
  const query = {
    matches,
    media: REDUCED_MOTION_QUERY,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn((_type: string, listener: MotionListener) => {
      listeners.add(listener);
    }),
    removeEventListener: vi.fn((_type: string, listener: MotionListener) => {
      listeners.delete(listener);
    }),
    dispatchEvent: vi.fn(),
  };
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn(() => query),
  });
  return {
    setMatches(next: boolean) {
      query.matches = next;
      for (const listener of listeners) listener({ matches: next } as MediaQueryListEvent);
    },
  };
}

/** Dispatches a pointermove with the fields a plain jsdom Event does not carry. */
function firePointerMove(element: HTMLElement, pointerType: string, x: number, y: number) {
  const event = Object.assign(new Event("pointermove", { bubbles: true }), {
    pointerType,
    clientX: x,
    clientY: y,
  });
  fireEvent(element, event);
}

/** Minimal card with the hook attached and a final value that must never move out of the DOM. */
function Probe() {
  const ref = useGlanceFx<HTMLDivElement>();
  return (
    <div className="glance-card" ref={ref}>
      <span className="glance-value">23 found</span>
    </div>
  );
}

beforeAll(async () => {
  await initI18n("en");
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  Object.defineProperty(window, "matchMedia", { configurable: true, value: originalMatchMedia });
});

describe("HumanSummary glance effects", () => {
  it("keeps each card's final value in the DOM while the mouse moves", () => {
    stubBoundingRect();
    const frames = queueFrames();
    const view = snapshot("secure_boot_off_self_view");
    const { container } = render(
      <HumanSummary view={view} header={view.header} texts={{}} onSwitchToTechnical={vi.fn()} />,
    );
    // Drop the odometer's mount frames; this test runs only the glance frame.
    frames.pending.length = 0;
    const cards = Array.from(container.querySelectorAll<HTMLElement>(".glance-card"));
    expect(cards).toHaveLength(3);
    const values = cards.map((node) => node.querySelector(".glance-value")?.textContent ?? "");
    expect(values.every((value) => value.length > 0)).toBe(true);
    const before = cards.map((node) => node.textContent);

    const card = cards[0];
    if (!card) throw new Error("no first glance card");
    firePointerMove(card, "mouse", 200, 0);
    expect(frames.pending.length).toBeGreaterThan(0);
    frames.flush();

    expect(card.style.getPropertyValue("--mx")).toBe("100%");
    expect(card.style.getPropertyValue("--my")).toBe("0%");
    expect(card.style.transform).toBe("perspective(700px) rotateX(-6deg) rotateY(-6deg)");
    expect(cards.map((c) => c.textContent)).toEqual(before);
  });

  it("stays still under reduced motion and re-checks on change", () => {
    stubBoundingRect();
    const media = stubMatchMedia(true);
    const frames = queueFrames();
    const { container } = render(<Probe />);
    const card = container.querySelector<HTMLElement>(".glance-card");
    if (!card) throw new Error("no probe card");
    expect(card.textContent).toContain("23 found");

    firePointerMove(card, "mouse", 200, 0);
    expect(frames.pending).toHaveLength(0);
    expect(card.style.getPropertyValue("--mx")).toBe("");
    expect(card.style.transform).toBe("");

    media.setMatches(false);
    firePointerMove(card, "mouse", 200, 0);
    expect(frames.pending.length).toBeGreaterThan(0);
    frames.flush();
    expect(card.style.getPropertyValue("--mx")).toBe("100%");

    media.setMatches(true);
    expect(card.style.getPropertyValue("--mx")).toBe("");
    expect(card.style.transform).toBe("");
    expect(card.textContent).toContain("23 found");
  });

  it("removes listeners and cancels a pending frame on unmount", () => {
    const add = vi.spyOn(EventTarget.prototype, "addEventListener");
    const remove = vi.spyOn(EventTarget.prototype, "removeEventListener");
    const frame = vi.spyOn(window, "requestAnimationFrame").mockReturnValue(7);
    const cancel = vi.spyOn(window, "cancelAnimationFrame").mockImplementation(() => {});
    const { container, unmount } = render(<Probe />);
    const card = container.querySelector<HTMLElement>(".glance-card");
    if (!card) throw new Error("no probe card");
    expect(add).toHaveBeenCalledWith("pointermove", expect.any(Function));
    expect(add).toHaveBeenCalledWith("pointerleave", expect.any(Function));

    firePointerMove(card, "mouse", 20, 20);
    expect(frame).toHaveBeenCalled();

    unmount();
    expect(cancel).toHaveBeenCalledWith(7);
    expect(remove).toHaveBeenCalledWith("pointermove", expect.any(Function));
    expect(remove).toHaveBeenCalledWith("pointerleave", expect.any(Function));
  });
});
