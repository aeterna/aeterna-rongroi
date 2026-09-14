// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useTranslation } from "react-i18next";
import type { StateFilter } from "../grouping";
import type { ListedCounts } from "../types";

interface Props {
  listed: ListedCounts;
  filter: StateFilter | null;
  onFilter: (filter: StateFilter | null) => void;
}

/**
 * Three counts of what the view lists, each a filter, and the sentence that no report proves a PC
 * clean directly under them. Never one number and never a fourth item (ADR 0002, ADR 0045).
 */
export function ReportSummary({ listed, filter, onFilter }: Props) {
  const { t } = useTranslation("report");
  const items: [StateFilter, number][] = [
    ["found", listed.found],
    ["not_found", listed.not_found],
    ["unmeasured", listed.unmeasured],
  ];
  return (
    <section className="summary" aria-labelledby="summary-title">
      <h2 id="summary-title">{t("summary.title")}</h2>
      <div className="tally">
        {items.map(([state, count]) => (
          <button
            key={state}
            type="button"
            className={`tally-item tally-${state}`}
            aria-pressed={filter === state}
            onClick={() => onFilter(filter === state ? null : state)}
          >
            <span className="count">
              <span className={`mark mark-${state}`} aria-hidden="true" />
              {count}
            </span>
            <span className="label">{t(`summary.${state}`)}</span>
          </button>
        ))}
      </div>
      <p className="never">{t("common:footer.evidence_only")}</p>
    </section>
  );
}
