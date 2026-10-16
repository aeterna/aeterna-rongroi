// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { saveSavedRecord } from "../api";
import type { SavedSummary } from "../types";

/** How many characters of the digest are shown large for staff to note (ADR 0073 §3). */
export const SHOWN_DIGEST_LEN = 16;

/** The first 16 characters of `digest` in four groups of four. */
export function shownDigest(digest: string): string {
  return (digest.slice(0, SHOWN_DIGEST_LEN).match(/.{1,4}/g) ?? []).join(" ");
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
  return (
    <section className="saved-record" aria-label={t("saved.label")}>
      {saved.case_code && (
        <p>
          {t("saved.case_code")} <strong className="case-code">{saved.case_code}</strong>
        </p>
      )}
      <p>
        {t("saved.digest")} <strong className="digest">{shownDigest(saved.digest)}</strong>
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
