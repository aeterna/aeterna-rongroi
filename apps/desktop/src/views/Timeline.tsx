// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// The timeline layer (ADR 0051). Which times reach it, and their order, are decided in
// `rongroi-core::view`; this file only shows them and filters by collector.

import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { RuleText, Timeline as TimelineData, TimelineEntry } from "../types";

interface Props {
  timeline: TimelineData;
  texts: Record<string, RuleText>;
}

export function Timeline({ timeline, texts }: Props) {
  const { t } = useTranslation("report");
  const [collector, setCollector] = useState<string>("");
  const collectors = [
    ...new Set(timeline.entries.flatMap((entry) => (entry.collector ? [entry.collector] : []))),
  ];
  // Anchors stay whatever the filter: they are what the other times are read against.
  const shown = timeline.entries.filter(
    (entry) => collector === "" || entry.collector === null || entry.collector === collector,
  );
  const selectors = [
    ...new Set(
      shown.flatMap((entry) =>
        entry.source.kind === "selector" ? [entry.source.selector_id] : [],
      ),
    ),
  ];
  const collectorName = (id: string) => t(`collector.${id}`, { defaultValue: id });

  return (
    <section className="timeline" aria-labelledby="timeline-title">
      <h3 id="timeline-title">{t("timeline.title")}</h3>
      {/* What the timeline never says, said above it (ADR 0051 decision 6). */}
      <p className="scope">{t("timeline.note")}</p>

      {timeline.bands.length > 0 && (
        <>
          <p className="muted">{t("timeline.coverage_note")}</p>
          <ul className="bands">
            {timeline.bands.map((band) => (
              <li key={`${band.collector}:${band.place ?? ""}:${band.subject ?? ""}`}>
                {t("timeline.coverage", {
                  source: [collectorName(band.collector), band.place, band.subject]
                    .filter(Boolean)
                    .join(" · "),
                  from: band.from,
                  to: band.to,
                })}
              </li>
            ))}
          </ul>
        </>
      )}

      {timeline.unmeasured.length > 0 && (
        <ul className="unmeasured-sources">
          {timeline.unmeasured.map((source) => (
            <li key={`${source.collector}:${source.place ?? ""}`}>
              {t("timeline.not_measured", {
                source: [collectorName(source.collector), source.place].filter(Boolean).join(" · "),
                reason: t(`reason.${source.reason}`),
              })}
            </li>
          ))}
        </ul>
      )}

      {collectors.length > 1 && (
        <label className="switch">
          {t("timeline.filter")}{" "}
          <select value={collector} onChange={(event) => setCollector(event.target.value)}>
            <option value="">{t("timeline.all")}</option>
            {collectors.map((id) => (
              <option key={id} value={id}>
                {collectorName(id)}
              </option>
            ))}
          </select>
        </label>
      )}

      <details open={shown.length <= 50}>
        <summary className="muted">{t("timeline.count", { count: shown.length })}</summary>
        <ol className="entries">
          {keyed(shown).map(([key, entry]) => (
            <li key={key}>
              <code>{entry.at}</code> <Entry entry={entry} texts={texts} />
            </li>
          ))}
        </ol>
      </details>

      {selectors.length > 0 && (
        <section className="selectors" aria-labelledby="timeline-selectors-title">
          <h4 id="timeline-selectors-title">{t("timeline.selectors")}</h4>
          {selectors.map((id) => {
            const text = texts[id];
            if (!text) {
              return null;
            }
            return (
              <div key={id} className="selector">
                <p>
                  <strong>{text.title}</strong> — {text.description}
                </p>
                <p className="muted">{t("timeline.selector_causes")}</p>
                <ul>
                  {text.falsepositives.map((cause) => (
                    <li key={cause}>{cause}</li>
                  ))}
                </ul>
              </div>
            );
          })}
        </section>
      )}
    </section>
  );
}

/** Each entry with a key made of what it says, and a count for the rare two that say the same. */
function keyed(entries: TimelineEntry[]): [string, TimelineEntry][] {
  const seen = new Map<string, number>();
  return entries.map((entry) => {
    const base = JSON.stringify(entry);
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    return [`${base}#${count}`, entry];
  });
}

function Entry({ entry, texts }: { entry: TimelineEntry; texts: Record<string, RuleText> }) {
  const { t } = useTranslation("report");
  const { source } = entry;
  if (source.kind === "anchor") {
    return (
      <strong>
        {entry.field === "generated_at" ? t("timeline.scan_time") : t("timeline.boot_time")}
      </strong>
    );
  }
  const where = [
    entry.collector ? t(`collector.${entry.collector}`, { defaultValue: entry.collector }) : null,
    entry.place,
    entry.subject,
  ]
    .filter(Boolean)
    .join(" · ");
  const from =
    source.kind === "evidence"
      ? (texts[source.rule_id]?.title ?? source.rule_id)
      : source.kind === "selector"
        ? (texts[source.selector_id]?.title ?? source.selector_id)
        : t("timeline.unmatched");
  return (
    <>
      {where} — <code>{entry.field}</code> <span className="muted">({from})</span>
    </>
  );
}
