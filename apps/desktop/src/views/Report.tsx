// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { reportView, ruleTexts } from "../api";
import type { Evidence, Mode, ReportView, RuleText } from "../types";

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

      {view.evidence.length === 0 && <p>{t("empty")}</p>}
      <ul className="evidence">
        {view.evidence.map((item) => (
          <EvidenceRow key={item.rule_id} item={item} text={texts[item.rule_id]} />
        ))}
      </ul>

      {mode === "ss" && (
        <p className="muted">
          {t("hidden", {
            notFound: view.hidden.not_found,
            unmeasured: view.hidden.unmeasured,
          })}
        </p>
      )}

      <button type="button" onClick={onBack}>
        {t("common:actions.back")}
      </button>
    </section>
  );
}

function EvidenceRow({ item, text }: { item: Evidence; text: RuleText | undefined }) {
  const { t } = useTranslation("report");
  let detail: string;
  switch (item.state) {
    case "found":
      detail = item.observations
        .flatMap((o) => Object.entries(o.fields).map(([k, v]) => `${k}=${String(v)}`))
        .join(", ");
      break;
    case "not_found":
      // The report keeps the English source text; the rule text carries the translation.
      detail = `${t("retention")}: ${text?.retention ?? item.retention}`;
      break;
    case "unmeasured":
      detail = t(`reason.${item.reason}`);
      break;
  }
  return (
    <li className={`evidence-${item.state}`}>
      <span className="state">{t(`state.${item.state}`)}</span>{" "}
      <span className="title">
        {t("check")}: {text?.title ?? item.rule_id}
      </span>{" "}
      <span className="muted">
        ({t(`strength.${item.strength}`)}, {item.collector})
      </span>
      <div className="detail">{detail}</div>
    </li>
  );
}
