// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { saveSavedRecord } from "../api";
import type { SavedSummary } from "../types";
import "./SavedRecordBox.motion.css";

/** How many characters of the digest are shown large for staff to note (ADR 0073 §3). */
export const SHOWN_DIGEST_LEN = 16;

/** The first 16 characters of `digest` in four groups of four. */
export function shownDigest(digest: string): string {
  return (digest.slice(0, SHOWN_DIGEST_LEN).match(/.{1,4}/g) ?? []).join(" ");
}

/** Characters the decode may show in a position that has not locked yet. */
const HEX_CHARS = "0123456789abcdef";
const DECODE_INTERVAL_MS = 40;
const DECODE_STEPS = 25; // 25 × 40 ms ≈ the ~1000 ms decode.

/** `true` when the reader asks for less motion; a missing `matchMedia` (tests, old webviews) means no. */
function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  try {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}

/** One random lowercase hex character. */
function randomHexChar(): string {
  const index = Math.floor(Math.random() * HEX_CHARS.length);
  return HEX_CHARS[index] ?? "0";
}

/** `target` with its first `locked` hex characters real; the group spaces never change. */
function decodeFrame(target: string, locked: number): string {
  let hexIndex = 0;
  let frame = "";
  for (const character of target) {
    if (character === " ") {
      frame += character;
      continue;
    }
    frame += hexIndex < locked ? character : randomHexChar();
    hexIndex += 1;
  }
  return frame;
}

/**
 * The decorative frame the visible digest shows while decoding, or `null` when it has settled. A
 * separate hidden span keeps the real value readable throughout. It runs once per digest.
 */
function useDecodeFrame(digest: string): string | null {
  const [frame, setFrame] = useState<string | null>(null);

  useEffect(() => {
    const final = shownDigest(digest);
    setFrame(null);
    if (prefersReducedMotion()) {
      return;
    }

    let step = 0;
    const timer = window.setInterval(() => {
      step += 1;
      if (step >= DECODE_STEPS) {
        window.clearInterval(timer);
        setFrame(null);
        return;
      }
      const hexCount = final.split(" ").join("").length;
      const locked = Math.floor((step / DECODE_STEPS) * hexCount);
      setFrame(decodeFrame(final, locked));
    }, DECODE_INTERVAL_MS);

    return () => window.clearInterval(timer);
  }, [digest]);

  return frame;
}

type SaveState =
  | { kind: "idle" }
  | { kind: "saved"; path: string }
  | { kind: "cancelled" }
  | { kind: "failed"; reason: string };

/**
 * The case code and the digest of the record this screen would save, and the Save button (ADR 0073). The
 * digest is of the bytes Rust built once at consent; Save writes those bytes, nothing rebuilt.
 */
export function SavedRecordBox({ saved }: { saved: SavedSummary }) {
  const { t } = useTranslation("report");
  const [state, setState] = useState<SaveState>({ kind: "idle" });
  const finalDigest = shownDigest(saved.digest);
  const frame = useDecodeFrame(saved.digest);
  return (
    <section className="saved-record" aria-label={t("saved.label")}>
      {saved.case_code && (
        <p>
          {t("saved.case_code")} <strong className="case-code">{saved.case_code}</strong>
        </p>
      )}
      <p>
        {t("saved.digest")}{" "}
        <strong className="digest">
          <span className="digest-final">{finalDigest}</span>
          <span className="digest-frame" aria-hidden="true">
            {frame ?? finalDigest}
          </span>
        </strong>
      </p>
      <p className="muted">
        <code>{saved.digest}</code>
      </p>
      <p className="muted">{t("saved.note")}</p>
      <button
        type="button"
        onClick={() =>
          void saveSavedRecord(t("saved.dialog_title")).then(
            (path) => setState(path ? { kind: "saved", path } : { kind: "cancelled" }),
            (error: unknown) => setState({ kind: "failed", reason: String(error) }),
          )
        }
      >
        {t("saved.button")}
      </button>
      {state.kind === "saved" && <p className="note">{t("saved.done", { path: state.path })}</p>}
      {state.kind === "cancelled" && <p className="muted">{t("saved.cancelled")}</p>}
      {state.kind === "failed" && (
        <p className="note">{t("saved.failed", { reason: state.reason })}</p>
      )}
    </section>
  );
}
