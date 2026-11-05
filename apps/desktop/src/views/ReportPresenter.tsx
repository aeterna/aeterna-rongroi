// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// E10: the technical view's presenter toolbar. It shows position only, never a state, and its
// counter is the one visible thing beside the toggle; the longer sentence is the live region.

import { useTranslation } from "react-i18next";
import type { PresenterState } from "./Report.presenter";
import "./Report.presenter.css";

interface Props {
  /** The ids of the groups the technical view is rendering, in order. */
  groupIds: string[];
  presenter: PresenterState;
}

/** The presenter toggle, its previous/next steps, the visible position and the live announcement. */
export function ReportPresenter({ groupIds, presenter }: Props) {
  const { t } = useTranslation("report");
  const total = groupIds.length;
  const safeIndex = total === 0 ? 0 : Math.min(presenter.index, total - 1);
  const current = total === 0 ? 0 : safeIndex + 1;
  const currentId = groupIds[safeIndex];
  const collector = currentId?.startsWith("group-") ? currentId.slice("group-".length) : currentId;
  const title = collector ? t(`collector.${collector}`, { defaultValue: collector }) : "";
  const position = t("presenter.counter", {
    defaultValue: "{{current}} / {{total}}",
    current,
    total,
  });

  return (
    <div className="presenter">
      <button
        type="button"
        className="presenter-toggle"
        aria-pressed={presenter.on}
        onClick={presenter.toggle}
      >
        {t("presenter.toggle", { defaultValue: "Presenter" })}
      </button>
      <button
        type="button"
        className="presenter-prev"
        onClick={presenter.prev}
        disabled={!presenter.on || total === 0}
      >
        {t("presenter.prev", { defaultValue: "Previous" })}
      </button>
      <span className="presenter-counter">{position}</span>
      <button
        type="button"
        className="presenter-next"
        onClick={presenter.next}
        disabled={!presenter.on || total === 0}
      >
        {t("presenter.next", { defaultValue: "Next" })}
      </button>
      <p className="presenter-status" role="status" aria-live="polite">
        {presenter.on && total > 0
          ? t("presenter.group", {
              defaultValue: "Group {{current}} of {{total}}: {{title}}",
              current,
              total,
              title,
            })
          : ""}
      </p>
    </div>
  );
}
