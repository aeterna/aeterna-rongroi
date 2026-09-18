// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { SsOptions } from "../types";

interface Props {
  /** Whether this scan was a full scan, whose extra reads the question must name (ADR 0052). */
  full: boolean;
  onAgree: (options: SsOptions) => void;
  onRefuse: () => void;
}

/**
 * SS-mode consent. Nothing from the report reaches the UI until the player agrees. After a full scan,
 * showing server identities is its own choice, off until the player turns it on (ADR 0052).
 */
export function Consent({ full, onAgree, onRefuse }: Props) {
  const { t } = useTranslation();
  const [serverIdentity, setServerIdentity] = useState(false);
  return (
    <section className="consent">
      <h2>{t("consent.title")}</h2>
      <ul>
        <li>{t("consent.reads")}</li>
        {full && <li>{t("consent.full_reads")}</li>}
        <li>{t("consent.shows")}</li>
        <li>{t("consent.sends")}</li>
        <li>{t("consent.webview")}</li>
      </ul>
      {full && (
        <label className="switch">
          <input
            type="checkbox"
            checked={serverIdentity}
            onChange={(event) => setServerIdentity(event.target.checked)}
          />{" "}
          {t("consent.server_identity")}
        </label>
      )}
      <p>
        <strong>{t("consent.refuse_ok")}</strong>
      </p>
      <div className="actions">
        <button
          type="button"
          onClick={() =>
            onAgree({ server_identity: full && serverIdentity, account_identifier: false })
          }
        >
          {t("consent.agree")}
        </button>
        <button type="button" onClick={onRefuse}>
          {t("consent.refuse")}
        </button>
      </div>
    </section>
  );
}
