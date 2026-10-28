// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useTranslation } from "react-i18next";
import type { ReportHeader, ReportView } from "../types";

interface Props {
  view: ReportView;
  header: ReportHeader;
  onStepClick?: (stepIndex: number) => void;
}

export function HorizonTimeline({ view, header, onStepClick }: Props) {
  const { t } = useTranslation("report");

  // Detect whether tamper rules matched
  const hasTamper = view.evidence.some((e) => e.strength === "tamper" && e.state === "found");
  const unmeasuredCount = view.listed.unmeasured;

  // Boot time summary
  let bootTimeTag = "-";
  let bootTimeSub = "";
  if (header.boot_time.state === "measured") {
    const hours = Math.floor(header.boot_time.seconds_since_boot / 3600);
    const days = Math.floor(hours / 24);
    bootTimeTag = days > 0 ? `${days}d ${hours % 24}h` : `${hours}h`;
    bootTimeSub = header.boot_time.booted_at.slice(0, 16).replace("T", " ");
  } else {
    bootTimeTag = t("strength.context");
    bootTimeSub = t("state.unmeasured_expected");
  }

  // FiveM session info from cross_source if present
  const sessionStmt = (view.cross_source ?? []).find((cs) => cs.kind === "session");
  const fivemCrossSource = (view.cross_source ?? []).find((cs) => cs.kind === "fivem_and_records");
  const fivemPlayedRecently = Boolean(sessionStmt || fivemCrossSource);
  let fivemTag = "-";
  let fivemSub = t("glance.fivem_none_text");
  if (
    sessionStmt &&
    sessionStmt.kind === "session" &&
    sessionStmt.session === "known" &&
    sessionStmt.before_scan
  ) {
    fivemTag = `${sessionStmt.before_scan.amount}${sessionStmt.before_scan.unit[0]}`;
    fivemSub = `FiveM ${sessionStmt.edition === "enhanced" ? "Enhanced" : "Legacy"}`;
  } else if (
    fivemCrossSource &&
    fivemCrossSource.kind === "fivem_and_records" &&
    fivemCrossSource.fivem.folders_days_before !== undefined
  ) {
    fivemTag = `${fivemCrossSource.fivem.folders_days_before}d`;
    fivemSub = `FiveM (${fivemCrossSource.fivem.editions.join(", ") || "Active"})`;
  } else if (fivemCrossSource && fivemCrossSource.kind === "fivem_and_records") {
    fivemTag = t("strength.presence");
    fivemSub = `FiveM (${fivemCrossSource.fivem.editions.join(", ") || "Active"})`;
  }

  // Earliest horizon tag: the install date names the anchor when it is known, otherwise the boot
  // time does (ADR 0084 decision 1).
  const anchors = view.trace_ages?.anchors ?? [];
  const installAnchor = anchors.find((a) => a.anchor === "install_date");
  const bootAnchor = anchors.find((a) => a.anchor === "boot_time");
  const oldestAnchor =
    installAnchor?.state === "measured"
      ? installAnchor
      : bootAnchor?.state === "measured"
        ? bootAnchor
        : undefined;
  // An anchor dated after the scan has no count, and its tag is "-" rather than a number made up for
  // it. The anchor is not swapped for another one to get a count (ADR 0088).
  const historyTag = oldestAnchor?.days_before !== undefined ? `${oldestAnchor.days_before}d` : "-";

  // Badge status
  let badgeText = t("horizon_timeline.badge_not_found");
  let badgeClass = "";
  if (hasTamper) {
    badgeText = t("horizon_timeline.badge_broken");
    badgeClass = "alert";
  } else if (unmeasuredCount > 5) {
    badgeText = t("horizon_timeline.badge_unmeasured");
    badgeClass = "warning";
  }

  return (
    <div className="timeline-card">
      <div className="timeline-head">
        <div className="timeline-title">
          <svg
            width="18"
            height="18"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#0869b0"
            strokeWidth="2.2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
          <span>{t("horizon_timeline.title")}</span>
        </div>
        <span className={`timeline-badge ${badgeClass}`}>{badgeText}</span>
      </div>

      <div className="timeline-track">
        <div className={`timeline-line ${hasTamper ? "broken" : ""}`} />

        {/* Step 0: History Origin */}
        <button
          type="button"
          className={`timeline-step ${hasTamper ? "alert" : ""}`}
          onClick={() => onStepClick?.(0)}
        >
          <div className="timeline-dot">
            <div className="timeline-dot-inner" />
          </div>
          <div>
            <div className="timeline-tag">{historyTag}</div>
            <div className="timeline-label">{t("horizon_timeline.step_history_start")}</div>
            {oldestAnchor?.anchor === "install_date" && (
              <div className="timeline-sub">
                {t("horizon_timeline.step_history_start_sub_install")}
              </div>
            )}
            {oldestAnchor?.anchor === "boot_time" && (
              <div className="timeline-sub">
                {t("horizon_timeline.step_history_start_sub_boot")}
              </div>
            )}
          </div>
        </button>

        {/* Step 1: Boot Time */}
        <button type="button" className="timeline-step" onClick={() => onStepClick?.(1)}>
          <div className="timeline-dot">
            <div className="timeline-dot-inner" />
          </div>
          <div>
            <div className="timeline-tag">{bootTimeTag}</div>
            <div className="timeline-label">{t("horizon_timeline.step_boot_time")}</div>
            <div className="timeline-sub">{bootTimeSub}</div>
          </div>
        </button>

        {/* Step 2: FiveM Session */}
        <button
          type="button"
          className={`timeline-step ${fivemPlayedRecently ? "" : "muted"}`}
          onClick={() => onStepClick?.(2)}
        >
          <div className="timeline-dot">
            <div className="timeline-dot-inner" />
          </div>
          <div>
            <div className="timeline-tag">{fivemTag}</div>
            <div className="timeline-label">{t("horizon_timeline.step_fivem_session")}</div>
            <div className="timeline-sub">{fivemSub}</div>
          </div>
        </button>

        {/* Step 3: Current Scan */}
        <button type="button" className="timeline-step active" onClick={() => onStepClick?.(3)}>
          <div className="timeline-dot">
            <div className="timeline-dot-inner" />
          </div>
          <div>
            <div className="timeline-tag">{t("horizon_timeline.step_current_scan_sub")}</div>
            <div className="timeline-label">{t("horizon_timeline.step_current_scan")}</div>
            <div className="timeline-sub">
              {header.generated_at ? header.generated_at.slice(0, 16).replace("T", " ") : ""}
            </div>
          </div>
        </button>
      </div>
    </div>
  );
}
