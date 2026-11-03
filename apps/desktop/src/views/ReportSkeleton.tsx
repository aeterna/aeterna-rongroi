// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useTranslation } from "react-i18next";
import "./Report.skeleton.css";

/** The report's shape while its view is still on the way; the blocks are decoration, the status is not. */
export function ReportSkeleton() {
  const { t } = useTranslation("report");
  return (
    <section className="report report-skeleton" aria-busy="true">
      <p className="visually-hidden" role="status">
        {t("skeleton.loading", { defaultValue: "Loading the report" })}
      </p>
      <div className="report-skeleton-block" aria-hidden="true" />
      <div className="report-skeleton-block" aria-hidden="true" />
      <div className="report-skeleton-block" aria-hidden="true" />
    </section>
  );
}
