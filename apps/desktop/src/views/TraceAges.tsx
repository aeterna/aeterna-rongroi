// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// The trace-ages section and the cross-source statements (ADR 0061, ADR 0062). What they hold, and
// when a statement exists at all, is decided in `rongroi-core::view`; this file only words them.
// Nothing here sorts, colours or compares a row.

import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import type {
  AgeText,
  AnchorAge,
  AnchorName,
  Comparison,
  CrossSourceStatement,
  Duration,
  RecordsStatement,
  SessionEnd,
  SessionLine,
  SessionStart,
  SessionStatement,
  SourceLine,
  TraceAge,
  TraceAges as TraceAgesData,
  UnmeasuredReason,
} from "../types";

/** The ordinary causes under the section, in ADR 0061's order, then ADR 0062 section 7's four. */
const CAUSES = [
  "reinstall",
  "cleanup",
  "log_size",
  "prefetch_off",
  "fivem_reinstalled",
  "moved",
  "clock",
  "index_rebuilt",
  "clear_cache",
  "copied_cache",
  "reinstall_kept_cache",
] as const;

/** The ordinary causes under the statement, in ADR 0061's order. */
const STATEMENT_CAUSES = [
  "reinstall",
  "cleanup",
  "prefetch_off",
  "fivem_reinstalled",
  "other_name",
  "windows_removes",
  "clock",
] as const;

function days(t: TFunction, count: number): string {
  return t("trace_ages.days_before", { count });
}

/** `not_admin` is "not known", never "empty"; `source_absent` and `source_empty` keep their words. */
function notRead(t: TFunction, reason: UnmeasuredReason): string {
  if (reason === "not_admin") {
    return t("trace_ages.not_admin");
  }
  if (reason === "source_absent" || reason === "source_empty") {
    return t(`reason.${reason}`);
  }
  return t("trace_ages.not_read", { reason: t(`reason.${reason}`) });
}

interface Props {
  ages: TraceAgesData;
  texts: Record<string, AgeText>;
}

export function TraceAges({ ages, texts }: Props) {
  const { t } = useTranslation("report");
  const collectors = [...new Set(ages.rows.map((row) => row.collector))];
  return (
    <section className="trace-ages" aria-labelledby="trace-ages-title">
      <h3 id="trace-ages-title">{t("trace_ages.title")}</h3>
      <p className="scope">{t("trace_ages.note")}</p>

      <h4>{t("trace_ages.anchors")}</h4>
      <ul className="anchors">
        {ages.anchors.map((anchor) => (
          <AnchorLine key={anchor.anchor} anchor={anchor} />
        ))}
      </ul>

      <h4>{t("trace_ages.sources")}</h4>
      {collectors.map((collector) => {
        const rows = ages.rows.filter((row) => row.collector === collector);
        const text = texts[collector];
        return (
          <div key={collector} className="trace-age-source">
            <p>
              <strong>{t(`collector.${collector}`, { defaultValue: collector })}</strong>
            </p>
            <ul>
              {rows.map((row) => (
                <li key={`${row.collector}:${row.place ?? ""}:${row.subject ?? ""}`}>
                  <RowLine row={row} />
                </li>
              ))}
              {collector === ages.folded_logs?.collector && (
                <li>
                  {t("trace_ages.folded", {
                    logs: ages.folded_logs.logs,
                    withRecords: ages.folded_logs.with_records,
                    notRead: ages.folded_logs.not_read,
                  })}
                </li>
              )}
            </ul>
            {text && (
              <p className="muted">
                {text.retention} (
                {text.documented ? t("trace_ages.documented") : t("trace_ages.not_documented")};{" "}
                {t("trace_ages.references")}: {text.references.join(", ")})
              </p>
            )}
          </div>
        );
      })}

      <p className="muted">{t("trace_ages.causes_intro")}</p>
      <ul>
        {CAUSES.map((cause) => (
          <li key={cause}>{t(`trace_ages.causes.${cause}`)}</li>
        ))}
      </ul>
    </section>
  );
}

function AnchorLine({ anchor }: { anchor: AnchorAge }) {
  const { t } = useTranslation("report");
  const kept = anchor.state === "measured" ? (anchor.kept ?? "") : "";
  const label = t(`trace_ages.anchor.${anchor.anchor}`, { kept });
  const value =
    anchor.state === "measured"
      ? t("trace_ages.on", { date: anchor.on, days: days(t, anchor.days_before) })
      : notRead(t, anchor.reason);
  return (
    <li>
      {label}: {value}
      <br />
      <span className="muted">{t(`trace_ages.resets.${anchor.anchor}`)}</span>
    </li>
  );
}

function RowLine({ row }: { row: TraceAge }) {
  const { t } = useTranslation("report");
  const name = [row.place ? t(`trace_ages.place.${row.place}`) : null, row.subject]
    .filter(Boolean)
    .join(" · ");
  const prefix = name ? `${name}: ` : "";
  if (row.state === "unmeasured") {
    return (
      <>
        {prefix}
        {notRead(t, row.reason)}
      </>
    );
  }
  const parts: string[] = [];
  if (row.oldest && row.days_before !== undefined) {
    parts.push(t("trace_ages.oldest", { at: row.oldest, days: days(t, row.days_before) }));
  } else {
    parts.push(t("trace_ages.holds_nothing"));
  }
  const countKey = row.place === "enhanced_server_cache" ? "enhanced_server_cache" : row.collector;
  parts.push(t(`trace_ages.count.${countKey}`, { count: row.count }));
  for (const [field, value] of Object.entries(row.extra ?? {})) {
    parts.push(t(`trace_ages.extra.${field}`, { value: String(value) }));
  }
  return (
    <>
      {prefix}
      {parts.join(", ")}
      {(row.index_beside ?? []).map((beside) => (
        <span key={beside.variant} className="muted">
          <br />
          {beside.oldest_file_created_on
            ? t("trace_ages.index_beside", {
                variant: beside.variant,
                index: beside.index_created_on,
                oldest: beside.oldest_file_created_on,
              })
            : t("trace_ages.index_beside_no_file", {
                variant: beside.variant,
                index: beside.index_created_on,
              })}
        </span>
      ))}
    </>
  );
}

/**
 * The cross-source statement, above the timeline in both modes. Every record gets its line, a record
 * that was not read is never folded into "no entry", and the causes are always printed in full.
 */
export function CrossSource({ statements }: { statements: CrossSourceStatement[] }) {
  return (
    <>
      {statements.map((statement) =>
        statement.kind === "session" ? (
          <Session key={JSON.stringify(statement)} statement={statement} />
        ) : (
          <Records key={JSON.stringify(statement)} statement={statement} />
        ),
      )}
    </>
  );
}

/** ADR 0061's statement: FiveM's side, one line per record, and the causes in full. */
function Records({ statement }: { statement: RecordsStatement }) {
  const { t } = useTranslation("report");
  const { fivem } = statement;
  const first = [
    fivem.editions.length > 0
      ? t("cross_source.present", {
          editions: fivem.editions
            .map((edition) => t(`cross_source.edition.${edition}`))
            .join(", "),
        })
      : t("cross_source.absent"),
    fivem.folders_written && fivem.folders_days_before !== undefined
      ? t("cross_source.folders_written", {
          date: fivem.folders_written,
          days: days(t, fivem.folders_days_before),
        })
      : null,
    fivem.server_folders > 0 && fivem.servers_written
      ? t("cross_source.servers", {
          count: fivem.server_folders,
          date: fivem.servers_written,
        })
      : null,
  ]
    .filter(Boolean)
    .join(" ");
  // The names once, on the first line that needs them; "those names" after.
  const firstNoEntry = statement.sources.findIndex((source) => source.line === "no_entry");
  return (
    <section className="cross-source" aria-labelledby="cross-source-title">
      <h3 id="cross-source-title">{t("cross_source.title")}</h3>
      <dl className="facts">
        <dt>{t("cross_source.fivem")}</dt>
        <dd>{first}</dd>
        {statement.sources.map((source, index) => (
          <SourceRow key={source.collector} source={source} named={index === firstNoEntry} />
        ))}
      </dl>
      <p className="muted">{t("cross_source.causes_intro")}</p>
      <ul>
        {STATEMENT_CAUSES.map((cause) => (
          <li key={cause}>{t(`cross_source.causes.${cause}`)}</li>
        ))}
      </ul>
    </section>
  );
}

function SourceRow({ source, named }: { source: SourceLine; named: boolean }) {
  const { t } = useTranslation("report");
  let line: string;
  switch (source.line) {
    case "selected":
      line = t("cross_source.selected", { count: source.entries, date: source.latest });
      break;
    case "no_entry":
      line = t(named ? "cross_source.no_entry_named" : "cross_source.no_entry", {
        count: source.entries,
        date: source.oldest,
        days: days(t, source.days_before),
      });
      break;
    case "could_not_show":
      line = t("cross_source.could_not_show");
      break;
    case "not_read":
      line =
        source.reason === "not_admin"
          ? t("cross_source.not_read_admin")
          : t("cross_source.not_read", { reason: t(`reason.${source.reason}`) });
      break;
    case "switched_off":
      line = t("cross_source.switched_off");
      break;
  }
  return (
    <>
      <dt>{t(`cross_source.source.${source.collector}`)}</dt>
      <dd>{line}</dd>
    </>
  );
}

/** "less than a minute", "1 hour", "25 hours". */
function duration(t: TFunction, value: Duration): string {
  if (value.unit === "minutes" && value.amount === 0) {
    return t("session.duration.less_than_a_minute");
  }
  return t(`session.duration.${value.unit}`, { count: value.amount });
}

function anchorName(t: TFunction, name: AnchorName): string {
  return t(`session.anchor_name.${name}`);
}

function startText(t: TFunction, start: SessionStart): string {
  switch (start.from) {
    case "process":
    case "prefetch":
      return t(`session.start.${start.from}`, { at: start.at, name: anchorName(t, start.name) });
    case "not_read":
      return t("session.start.not_read", { reason: t(`reason.${start.reason}`) });
    default:
      return t(`session.start.${start.from}`);
  }
}

function endText(t: TFunction, start: SessionStart, end: SessionEnd): string | null {
  switch (end.from) {
    case "still_running":
      // "Still running since T" already says it.
      return start.from === "process" ? null : t("session.end.still_running");
    case "bam":
      return t("session.end.bam", { at: end.at });
    case "not_read":
      return t("session.end.not_read", { reason: t(`reason.${end.reason}`) });
    default:
      return t("session.end.not_recorded");
  }
}

function comparisonText(t: TFunction, group: string, value: Comparison): string {
  return t(`session.${group}.${value.relation}`, { duration: duration(t, value.duration) });
}

function lineText(t: TFunction, line: SessionLine): string {
  switch (line.line) {
    case "compared": {
      // Enhanced's log folder names what it compares: the folder's latest log write (ADR 0062).
      const group = line.source === "enhanced_logs" ? "latest_log_write" : "written";
      return [
        line.created ? comparisonText(t, "created", line.created) : null,
        comparisonText(t, group, line.written),
      ]
        .filter(Boolean)
        .join("; ");
    }
    case "not_read":
      return t("session.not_read", { reason: t(`reason.${line.reason}`) });
    default:
      return t(`session.${line.line}`);
  }
}

/**
 * One edition's session statement (ADR 0062, as amended): the session's start and end with where each
 * came from, each source's line, the margin, and the ordinary causes in full — or that when FiveM last
 * ran is not known. Never compared with the scan's own time.
 */
function Session({ statement }: { statement: SessionStatement }) {
  const { t } = useTranslation("report");
  const title = t("session.title", { edition: t(`session.edition.${statement.edition}`) });
  const id = `session-title-${statement.edition}`;
  if (statement.session === "not_known") {
    const reason =
      statement.prefetch === statement.bam
        ? t(`reason.${statement.prefetch}`)
        : `${t(`reason.${statement.prefetch}`)}; ${t(`reason.${statement.bam}`)}`;
    return (
      <section className="cross-source" aria-labelledby={id}>
        <h3 id={id}>{title}</h3>
        <p>{t("session.not_known", { reason })}</p>
      </section>
    );
  }
  const session = [
    startText(t, statement.start),
    endText(t, statement.start, statement.end),
    statement.before_scan
      ? t("session.before_scan", { duration: duration(t, statement.before_scan) })
      : null,
  ]
    .filter(Boolean)
    .join("; ");
  const startRecorded = statement.start.from === "process" || statement.start.from === "prefetch";
  return (
    <section className="cross-source" aria-labelledby={id}>
      <h3 id={id}>{title}</h3>
      <dl className="facts">
        <dt>{t("session.session")}</dt>
        <dd>{session}</dd>
        {statement.lines.map((line) => {
          const source = t(`session.source.${line.source}`);
          const label = line.variant
            ? t("session.variant", { source, variant: line.variant })
            : source;
          return (
            <SessionRow key={`${line.source}:${line.variant ?? ""}`} label={label} line={line} />
          );
        })}
      </dl>
      {startRecorded && <p className="muted">{t("session.margin")}</p>}
      {statement.causes.includes("ended_abruptly") && (
        <p className="muted">{t("session.margin_end")}</p>
      )}
      <p className="muted">{t("session.causes_intro")}</p>
      <ul>
        {statement.causes.map((cause) => (
          <li key={cause}>{t(`session.causes.${cause}`)}</li>
        ))}
      </ul>
    </section>
  );
}

function SessionRow({ label, line }: { label: string; line: SessionLine }) {
  const { t } = useTranslation("report");
  return (
    <>
      <dt>{label}</dt>
      <dd>
        {lineText(t, line)}
        {line.join && (
          <>
            <br />
            <span className="muted">{t("session.join")}</span>
          </>
        )}
      </dd>
    </>
  );
}
