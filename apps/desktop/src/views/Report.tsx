// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { reportView, ruleTexts } from "../api";
import type { Evidence, Mode, Observation, ReportView, RuleText } from "../types";

interface Props {
  mode: Mode;
  onBack: () => void;
}

export function Report({ mode, onBack }: Props) {
  const { t, i18n } = useTranslation("report");
  const [view, setView] = useState<ReportView | null>(null);
  const [texts, setTexts] = useState<Record<string, RuleText>>({});

  useEffect(() => {
    void reportView(mode).then(setView);
  }, [mode]);

  useEffect(() => {
    void ruleTexts(i18n.language).then(setTexts);
  }, [i18n.language]);

  if (!view) {
    return null;
  }
  const { header } = view;
  const rights =
    header.elevated === null
      ? t("header.elevated_unknown")
      : header.elevated
        ? t("header.elevated_yes")
        : t("header.elevated_no");

  return (
    <section className="report">
      <dl className="facts">
        <dt>{mode === "ss" ? t("header.mode_ss") : t("header.mode_self")}</dt>
        <dd />
        <dt>{t("header.version")}</dt>
        <dd>{header.provenance.version}</dd>
        <dt>{t("header.platform")}</dt>
        <dd>{[header.platform, header.os_build].filter(Boolean).join(" ")}</dd>
        <dt>{t("header.rights")}</dt>
        <dd>{rights}</dd>
        <dt>{t("header.rules")}</dt>
        <dd>
          {header.rules_bundle.rule_count} · <code>{header.rules_bundle.sha256.slice(0, 12)}</code>
        </dd>
        {header.provenance.exe_sha256 && (
          <>
            <dt>{t("header.exe_sha256")}</dt>
            <dd>
              <code>{header.provenance.exe_sha256}</code>
            </dd>
          </>
        )}
      </dl>

      {/* Facts about the scan, not about the machine: each applies to every rule it stopped, so it
          is stated once here rather than as a row per rule (ADR 0027, ADR 0030). */}
      {view.scope.not_admin > 0 && (
        <p className="scope">{t("scope.not_admin", { checks: view.scope.not_admin })}</p>
      )}
      {view.scope.not_attempted > 0 && (
        <p className="scope">{t("scope.not_attempted", { checks: view.scope.not_attempted })}</p>
      )}

      {view.evidence.length === 0 && <p>{t("empty")}</p>}
      <ul className="evidence">
        {view.evidence.map((item) => (
          <EvidenceRow key={item.rule_id} item={item} text={texts[item.rule_id]} />
        ))}
      </ul>

      {/* Apart from the evidence, and shown in both modes: this is what the program itself left in
          what the collectors saw, not evidence about the PC (ADR 0010). */}
      {view.own_traces.length > 0 && (
        <section className="own-traces" aria-labelledby="own-traces-title">
          <h3 id="own-traces-title">{t("own_traces.title")}</h3>
          <p className="muted">{t("own_traces.note")}</p>
          <ul className="evidence">
            {view.own_traces.map((entry) => (
              <li key={`${entry.collector}:${fieldsOf(entry.observation)}`}>
                <span className="muted">({entry.collector})</span>
                <div className="detail">{fieldsOf(entry.observation)}</div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* After the evidence and the own traces: what the collectors saw that no rule matched. Self
          mode lists it; in SS mode the list is empty and it is counted below instead (ADR 0014). */}
      {view.unmatched.length > 0 && (
        <section className="unmatched" aria-labelledby="unmatched-title">
          <h3 id="unmatched-title">{t("unmatched.title")}</h3>
          <p className="muted">{t("unmatched.note")}</p>
          <ul className="evidence">
            {view.unmatched.flatMap((group) =>
              group.observations.map((observation) => (
                <li key={`${group.collector}:${fieldsOf(observation)}`}>
                  <span className="muted">({group.collector})</span>
                  <div className="detail">{fieldsOf(observation)}</div>
                </li>
              )),
            )}
          </ul>
        </section>
      )}

      {mode === "ss" && (
        <p className="muted">
          {t("hidden", {
            notFound: view.hidden.not_found,
            unmeasuredExpected: view.hidden.unmeasured_expected,
            unmeasuredUnexpected: view.hidden.unmeasured_unexpected,
            unmatched: view.hidden.unmatched,
          })}
        </p>
      )}

      <button type="button" onClick={onBack}>
        {t("common:actions.back")}
      </button>
    </section>
  );
}

/** One observation as a line of `field=value`, the way both lists show it. */
function fieldsOf(observation: Observation): string {
  return Object.entries(observation.fields)
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(", ");
}

function EvidenceRow({ item, text }: { item: Evidence; text: RuleText | undefined }) {
  const { t } = useTranslation("report");
  let detail: string;
  // A reason the rule itself declared in `unmeasured_when` is a different statement from one it did
  // not, and the reason alone does not tell them apart (ADR 0027).
  let stateKey: string = item.state;
  switch (item.state) {
    case "found":
      detail = item.observations.map(fieldsOf).join(", ");
      break;
    case "not_found":
      // The report keeps the English source text; the rule text carries the translation.
      detail = `${t("retention")}: ${text?.retention ?? item.retention}`;
      break;
    case "unmeasured":
      detail = t(`reason.${item.reason}`);
      stateKey = item.expected ? "unmeasured_expected" : "unmeasured_unexpected";
      break;
  }
  // What the rule means and what it does not prove goes beside every state; what legitimately
  // produces the same evidence goes beside a match, where there is something to explain (ADR 0027).
  const falsepositives = item.state === "found" ? (text?.falsepositives ?? []) : [];
  return (
    <li className={`evidence-${item.state}`}>
      <span className="state">{t(`state.${stateKey}`)}</span>{" "}
      <span className="title">
        {t("check")}: {text?.title ?? item.rule_id}
      </span>{" "}
      <span className="muted">
        ({t(`strength.${item.strength}`)}, {item.collector})
      </span>
      <div className="detail">{detail}</div>
      {text?.description && (
        <p className="description">
          {t("description")}: {text.description}
        </p>
      )}
      {falsepositives.length > 0 && (
        <div className="falsepositives">
          <p className="muted">{t("falsepositives")}:</p>
          <ul>
            {falsepositives.map((cause) => (
              <li key={cause}>{cause}</li>
            ))}
          </ul>
        </div>
      )}
    </li>
  );
}
