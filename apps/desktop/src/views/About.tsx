// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { codeLinks, reportHeader } from "../api";
import type { CodeLinks, ReportHeader } from "../types";
import { CodeLink } from "./CodeLink";

/** Where this program's code is and how to check that this file came from it (ADR 0045). */
export function About({ onBack }: { onBack: () => void }) {
  const { t } = useTranslation();
  const [header, setHeader] = useState<ReportHeader | null>(null);
  const [links, setLinks] = useState<CodeLinks | null>(null);

  useEffect(() => {
    void reportHeader().then(setHeader);
    void codeLinks().then(setLinks);
  }, []);

  if (!header || !links) {
    return null;
  }
  const { provenance, rules_bundle } = header;
  const repositoryName = links.repository.replace(/^https:\/\/github\.com\//, "");
  const asset = `aeterna-rongroi-${provenance.version}-windows-x64.exe`;

  return (
    <section className="about" aria-labelledby="about-title">
      <h2 id="about-title">{t("about.title")}</h2>
      <p className="muted">{t("about.intro")}</p>
      <div className="cards">
        <article className="card">
          <h3>{t("about.repository")}</h3>
          <CodeLink text={links.repository} copy={links.repository} qr />
        </article>
        <article className="card">
          <h3>{t("about.this_build_code")}</h3>
          {links.commit ? (
            <CodeLink text={links.code} copy={links.code} qr />
          ) : provenance.official ? (
            <p>{t("about.code_commit_unknown")}</p>
          ) : (
            <p>{t("about.code_unknown")}</p>
          )}
        </article>
        <article className="card">
          <h3>{t("about.this_file")}</h3>
          <dl className="facts">
            <dt>{t("about.build")}</dt>
            <dd>{provenance.official ? t("about.official") : t("banner.unofficial")}</dd>
            <dt>{t("about.version")}</dt>
            <dd>{provenance.version}</dd>
            <dt>{t("about.commit")}</dt>
            <dd>
              <code className="selectable">{provenance.commit ?? t("about.unknown")}</code>
            </dd>
            <dt>{t("about.exe_sha256")}</dt>
            <dd>
              <code className="selectable">{provenance.exe_sha256 ?? t("about.unknown")}</code>
            </dd>
            <dt>{t("about.rules")}</dt>
            <dd>
              {rules_bundle.rule_count} · <code className="selectable">{rules_bundle.sha256}</code>
            </dd>
            <dt>{t("about.license")}</dt>
            <dd>
              <code>GPL-3.0-or-later</code>
            </dd>
          </dl>
        </article>
        <article className="card">
          <h3>{t("about.verify_title")}</h3>
          <ol>
            <li>{t("about.verify_hash")}</li>
            <li>
              {t("about.verify_attestation")}{" "}
              <code className="selectable">{`gh attestation verify ${asset} -R ${repositoryName}`}</code>
            </li>
            <li>{t("about.verify_unofficial")}</li>
          </ol>
        </article>
        <article className="card wide">
          <h3>{t("about.no_web_title")}</h3>
          <p>{t("about.no_web_body")}</p>
          {/* ADR 0003: this wording is used verbatim wherever the program speaks about the network. */}
          <p>{t("consent.sends")}</p>
          <p>{t("consent.webview")}</p>
        </article>
      </div>
      <button type="button" onClick={onBack}>
        {t("actions.back")}
      </button>
    </section>
  );
}
