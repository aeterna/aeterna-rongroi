// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { withKeys } from "../keys";
import type { Evidence, Observation, RowBand, RuleFiles, RuleText } from "../types";
import { CodeLink } from "./CodeLink";
import "./EvidenceRow.expand.css";
import "./EvidenceRow.motion.css";

interface Props {
  item: Evidence;
  text: RuleText | undefined;
  /** The span this row's count is for, from the core, when it has one (ADR 0047, amendment of 2026-09-30). */
  band?: RowBand | undefined;
  /** `https://…/blob/<commit>` for an official build, `null` otherwise. */
  fileBase: string | null;
  /** `https://…/tree/<commit>` for an official build, `null` otherwise. */
  treeBase: string | null;
  /** Whether `codeLinks()` has arrived (successfully or not) — `false` while still in flight. */
  linksKnown: boolean;
  /** Whether the report header says this is an official build — apart from whether its commit is known. */
  official: boolean;
  technicalAll: boolean;
}

/**
 * One piece of evidence in three layers (ADR 0045): the row; what it means; technical details and
 * where it is in the code. A match starts open, because the sentence saying a rule proves no
 * cheating usually ends the description, which the two-line cut of a closed row hides.
 */
export function EvidenceRow({
  item,
  text,
  band,
  fileBase,
  treeBase,
  linksKnown,
  official,
  technicalAll,
}: Props) {
  const { t } = useTranslation("report");
  const [open, setOpen] = useState(item.state === "found");
  const [technical, setTechnical] = useState(false);
  const shown = open || technicalAll;
  const showTechnical = technical || technicalAll;
  const reduced = usePrefersReducedMotion();
  // The fold that opens and closes the body keeps it in the DOM from its first expansion on, so a
  // collapse animates and then hides it, instead of tearing it out; a row never expanded has no
  // body at all, as before.
  const [mounted, setMounted] = useState(item.state === "found");
  // Whether the fold is at its open height: it holds a freshly mounted body closed for one frame,
  // so the browser has a `0fr` start value to animate from, and drops it at once when closing.
  const [unfolded, setUnfolded] = useState(item.state === "found");
  // Whether the collapse has finished; only from then is the fold out of the accessibility tree.
  const [hidden, setHidden] = useState(false);
  const headRef = useRef<HTMLButtonElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (shown) {
      if (hidden) {
        setHidden(false);
        return;
      }
      if (!mounted) {
        setMounted(true);
        return;
      }
      if (unfolded) {
        return;
      }
      if (reduced) {
        // Reduced motion: the fold goes straight to its final open state, no start frame.
        setUnfolded(true);
        return;
      }
      const frame = window.requestAnimationFrame(() => setUnfolded(true));
      return () => window.cancelAnimationFrame(frame);
    }
    if (!mounted) {
      return;
    }
    if (unfolded) {
      setUnfolded(false);
      return;
    }
    if (hidden) {
      return;
    }
    if (reduced) {
      // Reduced motion: the fold is already at its closed state, nothing is left to time.
      setHidden(true);
      return;
    }
    // Let the fold run its full 200 ms collapse, then take the body out of the tree.
    const timer = window.setTimeout(() => setHidden(true), 200);
    return () => window.clearTimeout(timer);
  }, [shown, hidden, mounted, unfolded, reduced]);

  // Hand keyboard focus inside the body back to the head before it collapses, so focus is neither
  // lost on a node about to be hidden nor left behind when the fold turns inert.
  function toggleOpen() {
    const active = document.activeElement;
    if (shown && active instanceof HTMLElement && bodyRef.current?.contains(active)) {
      headRef.current?.focus();
    }
    setOpen(!shown);
  }

  // A reason the rule itself declared in `unmeasured_when` is a different statement from one it did
  // not, and the reason alone does not tell them apart (ADR 0027).
  const stateKey =
    item.state === "unmeasured"
      ? item.expected
        ? "unmeasured_expected"
        : "unmeasured_unexpected"
      : item.state;

  return (
    <li className={`row row-${item.state}`}>
      <button
        type="button"
        className="row-head"
        aria-expanded={shown}
        ref={headRef}
        // Carried fix (c): while every row is already forced open by the technical switch, a click
        // here must not silently change the row's own hidden `open` state for when it is switched off.
        disabled={technicalAll}
        onClick={toggleOpen}
      >
        <span className={`mark mark-${item.state}`} aria-hidden="true" />
        <span className="title-wrap">
          <span className="title">
            {t("check")}: {text?.title ?? item.rule_id}
          </span>
          <span className={`badge-strength badge-strength-${item.strength}`}>
            {t(`strength.${item.strength}`)}
          </span>
        </span>
        <span className="state">{t(`state.${stateKey}`)}</span>
        {!shown && text?.description && <span className="clamp">{text.description}</span>}
      </button>
      {mounted && (
        <div className="row-fold" data-open={unfolded ? "true" : "false"} inert={hidden}>
          <div className="row-body" ref={bodyRef}>
            <TelemetryLine item={item} />
            {text?.description && (
              <p className="description">
                {t("description")}: {text.description}
              </p>
            )}
            <Meaning item={item} text={text} />
            {band && <Band item={item} band={band} />}
            <button
              type="button"
              className="disclosure"
              aria-expanded={showTechnical}
              disabled={technicalAll}
              onClick={() => setTechnical(!technical)}
            >
              {t("layers.technical")}
            </button>
            {showTechnical && (
              <Technical
                item={item}
                text={text}
                fileBase={fileBase}
                treeBase={treeBase}
                linksKnown={linksKnown}
                official={official}
              />
            )}
          </div>
        </div>
      )}
    </li>
  );
}

/** Whether the platform asks for reduced motion; a missing `matchMedia` is not a reason to throw. */
function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** The platform's reduced-motion setting, followed when it changes while the row is open. */
function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(prefersReducedMotion);
  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return;
    }
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const onChange = () => setReduced(query.matches);
    setReduced(query.matches);
    if (typeof query.addEventListener !== "function") {
      return;
    }
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);
  return reduced;
}

/**
 * One monospace line naming the rule, the collector and the row's state (H6). The whole line is in
 * the DOM from the first render, for assistive technology and tests; the typed copy is decoration.
 */
function TelemetryLine({ item }: { item: Evidence }) {
  const line = `rule ${item.rule_id} - collector ${item.collector} - state ${item.state}`;
  const reduced = usePrefersReducedMotion();
  const [typed, setTyped] = useState(reduced ? line : "");

  useEffect(() => {
    if (reduced) {
      setTyped(line);
      return;
    }
    setTyped("");
    let index = 0;
    const timer = setInterval(() => {
      index += 1;
      setTyped(line.slice(0, index));
      if (index >= line.length) {
        clearInterval(timer);
      }
    }, 12);
    return () => clearInterval(timer);
  }, [line, reduced]);

  return (
    <p className="row-telemetry">
      <span className="row-telemetry-hidden">{line}</span>
      <span className="row-telemetry-typed" aria-hidden="true">
        {typed}
      </span>
    </p>
  );
}

function Meaning({ item, text }: { item: Evidence; text: RuleText | undefined }) {
  const { t } = useTranslation("report");
  switch (item.state) {
    case "found": {
      // What legitimately produces the same evidence goes beside a match (ADR 0027).
      const causes = text?.falsepositives ?? [];
      return causes.length === 0 ? null : (
        <div className="falsepositives">
          <p className="falsepositives-title">{t("falsepositives")}:</p>
          <ul>
            {causes.map((cause) => (
              <li key={cause}>{cause}</li>
            ))}
          </ul>
        </div>
      );
    }
    case "not_found":
      // The report keeps the English source text; the rule text carries the translation.
      return (
        <p className="detail">
          {t("retention")}: {text?.retention ?? item.retention}
        </p>
      );
    case "unmeasured":
      return <p className="detail">{t(`reason.${item.reason}`)}</p>;
  }
}

/**
 * The span the row's count is for, beside it: a count the change journal gives is for the span it
 * still held, and without the span "nothing deleted" reads as "nothing was ever deleted".
 */
function Band({ item, band }: { item: Evidence; band: RowBand }) {
  const { t } = useTranslation("report");
  if (band.state === "no_span") {
    return <p className="detail">{t("row_band.none")}</p>;
  }
  const key = item.state === "not_found" ? "row_band.not_found" : "row_band.found";
  return <p className="detail">{t(key, { from: band.from, to: band.to })}</p>;
}

function CopyJsonButton({ json }: { json: string }) {
  const { t } = useTranslation("report");
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");

  useEffect(() => {
    if (copied !== "copied") {
      return;
    }
    const timer = setTimeout(() => setCopied("idle"), 1500);
    return () => clearTimeout(timer);
  }, [copied]);

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(json);
      setCopied("copied");
    } catch {
      setCopied("failed");
    }
  }

  return (
    <>
      {/* The label keeps saying what the button does for assistive technology; the check beside it
          is decoration. The 1.5 s announcement of the copy lives outside, so it never joins the
          button's own accessible name. */}
      <button
        type="button"
        className={`copy-json-btn${copied === "copied" ? " copy-json-btn-copied" : ""}`}
        onClick={() => void onCopy()}
        aria-label={t("layers.copy_json")}
      >
        <span className="copy-json-check" aria-hidden="true" />
        {copied === "copied" ? t("layers.copied") : t("layers.copy_json")}
      </button>
      <span className="visually-hidden" aria-live="polite">
        {copied === "copied" ? t("layers.copied") : ""}
      </span>
    </>
  );
}

function Technical({
  item,
  text,
  fileBase,
  treeBase,
  linksKnown,
  official,
}: {
  item: Evidence;
  text: RuleText | undefined;
  fileBase: string | null;
  treeBase: string | null;
  linksKnown: boolean;
  official: boolean;
}) {
  const { t } = useTranslation("report");
  const observations: Observation[] = item.state === "found" ? item.observations : [];
  return (
    <div className="technical">
      {withKeys(observations, (observation) => JSON.stringify(observation.fields)).map(
        ([key, observation]) => (
          <div className="observation-block" key={key}>
            <div className="observation-header">
              <span className="observation-caption">{t("layers.observation")}</span>
              <CopyJsonButton json={JSON.stringify(observation.fields, null, 2)} />
            </div>
            <table className="fields">
              <thead>
                <tr>
                  <th scope="col">{t("layers.field")}</th>
                  <th scope="col">{t("layers.value")}</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(observation.fields).map(([field, value]) => (
                  <tr key={field}>
                    <th scope="row">{field}</th>
                    <td>
                      <code className="selectable">{String(value)}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ),
      )}
      <dl className="facts">
        <dt>{t("layers.rule_id")}</dt>
        <dd>
          <code className="selectable">{item.rule_id}</code>
        </dd>
        {text && (
          <>
            <dt>{t("layers.status")}</dt>
            <dd>
              <code>{text.status}</code>
            </dd>
          </>
        )}
        <dt>{t("layers.collector")}</dt>
        <dd>
          <code>{item.collector}</code>
        </dd>
        <dt>{t("layers.strength")}</dt>
        <dd>
          {t(`strength.${item.strength}`)} (<code>{item.strength}</code>)
        </dd>
        {item.state === "unmeasured" && (
          <>
            <dt>{t("layers.reason")}</dt>
            <dd>
              <code>
                {item.reason} · expected={String(item.expected)}
              </code>
            </dd>
          </>
        )}
      </dl>
      {text && (
        <Files
          files={text.files}
          fileBase={fileBase}
          treeBase={treeBase}
          linksKnown={linksKnown}
          official={official}
        />
      )}
    </div>
  );
}

function Files({
  files,
  fileBase,
  treeBase,
  linksKnown,
  official,
}: {
  files: RuleFiles;
  fileBase: string | null;
  treeBase: string | null;
  linksKnown: boolean;
  official: boolean;
}) {
  const { t } = useTranslation("report");
  const paths: [string, string, string | null][] = [
    ["layers.rule_file", files.rule, fileBase && `${fileBase}/${files.rule}`],
    ["layers.fixtures", files.fixtures, treeBase && `${treeBase}/${files.fixtures}`],
    ["layers.collector_file", files.collector, fileBase && `${fileBase}/${files.collector}`],
  ];
  // Whether the commit is known and whether the build is official are two facts: an official build
  // whose commit was not recorded is still official.
  const filesSentence = fileBase
    ? t("layers.files_at_commit")
    : official
      ? t("layers.files_commit_unknown")
      : t("layers.files_unknown_build");
  return (
    <section className="rule-files" aria-label={t("layers.code_title")}>
      <p className="muted">
        {t("layers.code_title")}
        {/* Carried fix (b): neither statement until it is known whether this build's commit is
            known — a call still in flight, or one that failed, is not evidence either way. */}
        {linksKnown && <> · {filesSentence}</>}
      </p>
      <ul>
        {paths.map(([label, path, link]) => (
          <li key={label}>
            <span className="muted">{t(label)}</span> <CodeLink text={path} copy={link} />
          </li>
        ))}
        {files.references.map((url) => (
          <li key={url}>
            <span className="muted">{t("layers.reference")}</span>{" "}
            <CodeLink text={url} copy={url} />
          </li>
        ))}
      </ul>
    </section>
  );
}
