// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// One switch for the app's decoration motion: the reader can turn it off themselves, on top of the
// platform's reduced-motion preference. It never changes what a result says.

import { useSyncExternalStore } from "react";

const KEY = "rongroi.motion";
const MOTION_EVENT = "rongroi:motion";
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

/** Whether the reader turned animation off with the app's own switch. */
export function animationsOff(): boolean {
  return document.documentElement.dataset.motion === "off";
}

/** Whether motion should be reduced: by the app's switch or by the platform preference. */
export function motionReduced(): boolean {
  if (animationsOff()) return true;
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  try {
    return window.matchMedia(REDUCED_MOTION_QUERY).matches;
  } catch {
    // A webview that cannot answer the query has not asked for reduced motion.
    return false;
  }
}

/** Turns the app's motion decoration off or on, remembers the choice and tells listeners. */
export function setAnimationsOff(off: boolean): void {
  if (off) {
    document.documentElement.dataset.motion = "off";
  } else {
    delete document.documentElement.dataset.motion;
  }
  try {
    window.localStorage.setItem(KEY, off ? "off" : "on");
  } catch {
    // Storage can be unavailable; the choice still holds for this window.
  }
  window.dispatchEvent(new Event(MOTION_EVENT));
}

/** Applies the remembered choice before the first render; nothing stored means the platform decides. */
export function initMotion(): void {
  try {
    const stored = window.localStorage.getItem(KEY);
    if (stored === "off") {
      document.documentElement.dataset.motion = "off";
    } else if (stored === "on") {
      delete document.documentElement.dataset.motion;
    }
  } catch {
    // Storage can be unavailable; the platform preference stays in charge.
  }
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener(MOTION_EVENT, onChange);
  return () => window.removeEventListener(MOTION_EVENT, onChange);
}

/** The app's switch as React state, so a control re-renders when the reader flips it. */
export function useAnimationsOff(): boolean {
  return useSyncExternalStore(subscribe, animationsOff, animationsOff);
}
