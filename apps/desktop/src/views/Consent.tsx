// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useTranslation } from "react-i18next";

interface Props {
  onAgree: () => void;
  onRefuse: () => void;
}

/** SS-mode consent. Nothing from the report reaches the UI until the player agrees. */
export function Consent({ onAgree, onRefuse }: Props) {
  const { t } = useTranslation();
  return (
    <section className="consent">
      <h2>{t("consent.title")}</h2>
      <ul>
        <li>{t("consent.reads")}</li>
        <li>{t("consent.shows")}</li>
        <li>{t("consent.sends")}</li>
        <li>{t("consent.webview")}</li>
      </ul>
      <p>
        <strong>{t("consent.refuse_ok")}</strong>
      </p>
      <div className="actions">
        <button type="button" onClick={onAgree}>
          {t("consent.agree")}
        </button>
        <button type="button" onClick={onRefuse}>
          {t("consent.refuse")}
        </button>
      </div>
    </section>
  );
}
