// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useTranslation } from "react-i18next";

/** Shown on every screen of a build that did not come from the release workflow (ADR 0007). */
export function UnofficialBanner() {
  const { t } = useTranslation();
  return (
    <div className="banner" role="alert">
      <strong>{t("banner.unofficial")}</strong> — {t("banner.unofficial_body")}
    </div>
  );
}
