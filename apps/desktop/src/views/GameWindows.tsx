// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// The game-window section (ADR 0078, P6 decisions 3–7). Which programs are listed, which facts hold
// and what is counted instead of named are decided in `rongroi-core::view`; this file only words
// them. Nothing here scores, orders or colours a program beyond the one found mark.

import { Fragment } from "react";
import { useTranslation } from "react-i18next";
import type { GameCandidate, IdentityFact, Mode, ReportView, TimeFact } from "../types";

type WindowKey = "before" | "during" | "after" | "before_scan";
const WINDOW_KEYS: WindowKey[] = ["before", "during", "after", "before_scan"];
// Unmatched installs are counted for the three windows around a session, not for the scan's own span.
const INSTALL_WINDOW_KEYS: ("before" | "during" | "after")[] = ["before", "during", "after"];
type IdentityKey = "i1" | "i2" | "i3" | "i4" | "l1";
type TimeKey = "t1" | "t2" | "t3" | "t4";

/** The game-window section, shown after the latest-session statement in both modes (ADR 0078). */
export function GameWindowsSection({ view, mode }: { view: ReportView; mode: Mode }) {
  const { t } = useTranslation("report");
  const windows = view.game_windows;
  if (!windows) {
    return null;
  }
  const self = mode !== "ss";
  return (
    <section className="game-windows" aria-labelledby="game-windows-title">
      <div className="game-head">
        <h3 id="game-windows-title">{t("game.title")}</h3>
        <span className="game-experimental">{t("game.experimental")}</span>
      </div>
      <p>{t("game.intro")}</p>
      {!self && <p>{t("game.ss_rule")}</p>}

      <dl className="game-facts">
        {windows.sessions.map((session, index) => {
          const range = session.end ? `${session.start} – ${session.end}` : session.start;
          const position = session.latest
            ? t("game.session.latest")
            : t("game.session.earlier", { at: session.start });
          return (
            <Fragment key={`${session.edition}:${session.start}:${index}`}>
              <dt>{`${t("session.session")} ${t(`session.edition.${session.edition}`)}`}</dt>
              <dd>{`${range} ${position}`}</dd>
              {session.latest && session.l1 && (
                <>
                  <dt>{t("game.session.l1_label")}</dt>
                  <dd>
                    {session.l1.fact === "true"
                      ? t("game.session.l1", { count: session.loaded_outside ?? 0 })
                      : session.l1.fact === "false"
                        ? t("game.fact.l1_false")
                        : t(`game.nk.${session.l1.reason.reason}`)}
                  </dd>
                </>
              )}
            </Fragment>
          );
        })}
      </dl>

      {self && (
        <ul className="game-chips">
          {WINDOW_KEYS.map((key) => (
            <li key={key} className="game-chip">
              {`${t(`game.window.${key}`)} · ${windows.counts[key]}`}
            </li>
          ))}
        </ul>
      )}
      {!self && windows.unnamed && (
        <p className="muted">
          {t("game.ss_counts", {
            list: WINDOW_KEYS.map(
              (key) => `${t(`game.window.${key}`)} ${windows.unnamed?.[key] ?? 0}`,
            ).join(" · "),
          })}
        </p>
      )}

      {windows.unmatched_installs &&
        INSTALL_WINDOW_KEYS.map((key) => {
          const count = windows.unmatched_installs?.[key] ?? 0;
          return count > 0 ? (
            <p key={key} className="muted">
              {`${t(`game.window.${key}`)}: ${t("game.note.unmatched_installs", { count })}`}
            </p>
          ) : null;
        })}

      {windows.clock?.changes.map((change) => (
        <p key={change.changed_at}>
          {t("game.clock.changed", {
            at: change.changed_at,
            detail:
              change.old_time && change.new_time
                ? t("game.clock.detail", { old: change.old_time, new: change.new_time })
                : "",
          })}
        </p>
      ))}
      {windows.clock?.history === "not_known" && <p>{t("game.clock.not_known")}</p>}

      <p className="muted">{t("game.order")}</p>
      <p className="muted">{t("game.windows_unmeasured")}</p>

      {windows.candidates.map((candidate, index) => (
        <CandidateCard key={`${candidate.name}:${index}`} candidate={candidate} />
      ))}
    </section>
  );
}

/** One program recorded near a session: its name, path, the facts that hold and the notes. */
function CandidateCard({ candidate }: { candidate: GameCandidate }) {
  const { t } = useTranslation("report");
  const identity: [IdentityKey, IdentityFact | undefined][] = [
    ["i1", candidate.i1],
    ["i2", candidate.i2],
    ["i3", candidate.i3],
    ["i4", candidate.i4],
    ["l1", candidate.l1],
  ];
  const times: [TimeKey, TimeFact][] = [
    ["t1", candidate.t1],
    ["t2", candidate.t2],
    ["t3", candidate.t3],
    ["t4", candidate.t4],
  ];
  // Unknown identity facts are said in words, never left out: an absent line would read as "no".
  const unknownFacts = identity.flatMap(([key, fact]) =>
    fact?.fact === "not_known" ? [{ key, reason: fact.reason.reason }] : [],
  );
  const { near, found } = candidate.near_sessions;
  const installs = candidate.installed_at ?? [];

  return (
    <article className="game-candidate">
      <p>
        <code>{candidate.name}</code>
      </p>
      {candidate.path && (
        <p className="muted">
          <code>{candidate.path}</code>
        </p>
      )}
      <ul className="game-labels">
        {identity.map(([key, fact]) =>
          fact?.fact === "true" ? (
            <li key={key} className="game-label game-label-found">
              <span className="mark mark-found" aria-hidden="true" />
              {`${t(`game.fact.${key}`)} (${t(`game.cause.${key}`)})`}
            </li>
          ) : null,
        )}
        {times.map(([key, fact]) =>
          fact.fact === "true" ? (
            <li key={key} className="game-label">
              {`${t(`game.fact.${key}`)} (${t(`game.cause.${key}`)})`}
            </li>
          ) : null,
        )}
        {near >= 2 && (
          <li className="game-label">
            {`${t("game.fact.r", { near, found })} (${t("game.cause.r")})`}
          </li>
        )}
        {unknownFacts.map(({ key, reason }) => (
          <li key={key} className="muted">
            {`${t(`game.fact.${key}`)}: ${t(`game.nk.${reason}`)}`}
          </li>
        ))}
      </ul>
      {(installs.length > 0 || candidate.refused_by_code_integrity) && (
        <ul className="game-notes">
          {installs.map((at) => (
            <li key={at} className="muted">
              {t("game.note.installed", { at })}
            </li>
          ))}
          {candidate.refused_by_code_integrity && (
            <li className="muted">{t("game.note.code_integrity")}</li>
          )}
        </ul>
      )}
    </article>
  );
}
