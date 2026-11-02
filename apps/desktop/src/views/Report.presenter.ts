// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// E10: presenter mode for SS mode. It moves one position through the technical view's groups and
// dims the others by position only; no group's state or identity ever decides what is current.

import { useEffect, useState } from "react";

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

/** Reads the user's motion preference; a missing matchMedia (tests, jsdom) counts as no request. */
function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia(REDUCED_MOTION_QUERY).matches;
}

/** True when the event lands in a field that owns the arrow, Home and End keys itself. */
function isEditing(target: EventTarget | null): boolean {
  if (typeof HTMLElement === "undefined" || !(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  return target.closest("input, textarea, select, [contenteditable]") !== null;
}

/** The palette owns the keyboard while it is open, including Escape. */
function paletteIsOpen(): boolean {
  if (typeof document === "undefined") return false;
  return document.querySelector(".palette-dialog, [role=dialog]") !== null;
}

/** Keeps a position inside the groups that are on screen; an empty list has no position. */
function clampIndex(index: number, total: number): number {
  if (total === 0) return 0;
  return Math.min(Math.max(index, 0), total - 1);
}

export interface PresenterState {
  /** Whether presenter mode is on. */
  on: boolean;
  toggle: () => void;
  /** The current group's zero-based position in `groupIds`. */
  index: number;
  next: () => void;
  prev: () => void;
  first: () => void;
  last: () => void;
  off: () => void;
}

/**
 * Presenter mode's position and keys. `enabled` is false outside the technical view or outside SS
 * mode, and turning it off resets the position: presenter mode is never persisted.
 */
export function usePresenter(groupIds: string[], enabled: boolean): PresenterState {
  const [on, setOn] = useState(false);
  const [index, setIndex] = useState(0);
  const total = groupIds.length;
  const currentId = groupIds[clampIndex(index, total)] ?? null;

  useEffect(() => {
    if (enabled) return;
    setOn(false);
    setIndex(0);
  }, [enabled]);

  useEffect(() => {
    setIndex((current) => clampIndex(current, total));
  }, [total]);

  useEffect(() => {
    if (!on || !enabled || currentId === null) return;
    const target = document.getElementById(currentId);
    if (!target || typeof target.scrollIntoView !== "function") return;
    target.scrollIntoView({
      behavior: prefersReducedMotion() ? "auto" : "smooth",
      block: "start",
    });
  }, [on, enabled, currentId]);

  useEffect(() => {
    if (!on || !enabled) return undefined;

    function onKeyDown(event: KeyboardEvent): void {
      if (event.defaultPrevented) return;
      if (event.ctrlKey || event.metaKey || event.altKey) return;
      if (isEditing(event.target) || isEditing(document.activeElement)) return;
      if (paletteIsOpen()) return;

      switch (event.key) {
        case "ArrowRight":
        case "ArrowDown":
        case "PageDown":
          event.preventDefault();
          setIndex((current) => clampIndex(current + 1, total));
          break;
        case "ArrowLeft":
        case "ArrowUp":
        case "PageUp":
          event.preventDefault();
          setIndex((current) => clampIndex(current - 1, total));
          break;
        case "Home":
          event.preventDefault();
          setIndex(0);
          break;
        case "End":
          event.preventDefault();
          setIndex(clampIndex(total - 1, total));
          break;
        case "Escape":
          event.preventDefault();
          setOn(false);
          setIndex(0);
          break;
        default:
          break;
      }
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [on, enabled, total]);

  function toggle(): void {
    if (!enabled) return;
    if (on) {
      setOn(false);
      setIndex(0);
      return;
    }
    setIndex(0);
    setOn(true);
  }

  function next(): void {
    if (!enabled) return;
    setIndex((current) => clampIndex(current + 1, total));
  }

  function prev(): void {
    if (!enabled) return;
    setIndex((current) => clampIndex(current - 1, total));
  }

  function first(): void {
    if (!enabled) return;
    setIndex(0);
  }

  function last(): void {
    if (!enabled) return;
    setIndex(clampIndex(total - 1, total));
  }

  function off(): void {
    setOn(false);
    setIndex(0);
  }

  return { on, toggle, index, next, prev, first, last, off };
}
