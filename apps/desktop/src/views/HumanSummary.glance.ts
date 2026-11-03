// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { type RefObject, useEffect, useRef } from "react";
import { motionReduced } from "../motion";

/** The media query that switches the whole decoration off. */
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

/** The most the card turns on either axis, in degrees. */
const MAX_TILT_DEG = 6;

/** Reads the motion preference; a missing matchMedia (tests, jsdom) is no request, never a throw. */
function prefersReducedMotion(): boolean {
  return motionReduced();
}

/**
 * H2 spotlight and H3 tilt for one glance card. Pointer moves set --mx/--my at most once per
 * animation frame, and the transform never turns more than {@link MAX_TILT_DEG} degrees per axis.
 * Only decoration changes: the evidence text stays in the DOM and is never rewritten here.
 * With `enabled` false the card is left untouched, the same as under reduced motion.
 */
export function useGlanceFx<T extends HTMLElement>(enabled = true): RefObject<T | null> {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    if (!enabled) return undefined;
    const card = ref.current;
    if (!card) return undefined;

    let reduced = prefersReducedMotion();
    let frame = 0;
    let pending: { x: number; y: number } | null = null;

    const reset = () => {
      pending = null;
      if (frame !== 0) {
        window.cancelAnimationFrame(frame);
        frame = 0;
      }
      card.style.removeProperty("--mx");
      card.style.removeProperty("--my");
      card.style.removeProperty("transform");
    };

    const apply = () => {
      frame = 0;
      const point = pending;
      pending = null;
      if (!point) return;

      const rect = card.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return;

      const x = Math.min(Math.max((point.x - rect.left) / rect.width, 0), 1);
      const y = Math.min(Math.max((point.y - rect.top) / rect.height, 0), 1);
      card.style.setProperty("--mx", `${x * 100}%`);
      card.style.setProperty("--my", `${y * 100}%`);
      // Both axes face the pointer; the perspective keeps the turn shallow instead of flat.
      const tiltX = (y - 0.5) * 2 * MAX_TILT_DEG;
      const tiltY = (0.5 - x) * 2 * MAX_TILT_DEG;
      card.style.transform = `perspective(700px) rotateX(${tiltX}deg) rotateY(${tiltY}deg)`;
    };

    const onPointerMove = (event: PointerEvent) => {
      if (reduced || event.pointerType !== "mouse") return;
      pending = { x: event.clientX, y: event.clientY };
      if (frame === 0) frame = window.requestAnimationFrame(apply);
    };

    const onPointerLeave = () => reset();

    const query =
      typeof window.matchMedia === "function" ? window.matchMedia(REDUCED_MOTION_QUERY) : null;
    const onMotionChange = () => {
      reduced = motionReduced();
      if (reduced) reset();
    };

    card.addEventListener("pointermove", onPointerMove);
    card.addEventListener("pointerleave", onPointerLeave);
    window.addEventListener("rongroi:motion", onMotionChange);
    if (query && typeof query.addEventListener === "function") {
      query.addEventListener("change", onMotionChange);
    }

    return () => {
      reset();
      card.removeEventListener("pointermove", onPointerMove);
      card.removeEventListener("pointerleave", onPointerLeave);
      window.removeEventListener("rongroi:motion", onMotionChange);
      if (query && typeof query.removeEventListener === "function") {
        query.removeEventListener("change", onMotionChange);
      }
    };
  }, [enabled]);

  return ref;
}
