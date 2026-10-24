// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Evidence, ReportHeader, ReportView, RuleText } from "../types";
import { HorizonTimeline } from "./HorizonTimeline";

interface Props {
  view: ReportView;
  header: ReportHeader;
  texts: Record<string, RuleText>;
  onSwitchToTechnical: () => void;
}

export function HumanSummary({ view, header, texts, onSwitchToTechnical }: Props) {
  const { t } = useTranslation("report");
  const [currentCategory, setCurrentCategory] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [openRows, setOpenRows] = useState<Record<string, boolean>>({});

  const foundItems = view.evidence.filter((e) => e.state === "found");
  const unmeasuredItems = view.evidence.filter((e) => e.state === "unmeasured");

  const tamperCount = foundItems.filter((e) => e.strength === "tamper").length;
  const hasTamper = tamperCount > 0;
  const unmeasuredCount = view.listed.unmeasured;

  // Hero note banner text: counts, not a verdict (ADR 0084 decision 1).
  let heroDesc = t("common:footer.evidence_only");
  let heroAlertClass = "";
  if (hasTamper) {
    heroDesc = t("hero_note.reassurance_tamper", { count: tamperCount });
    heroAlertClass = "warning";
  } else if (unmeasuredCount > 5) {
    heroDesc = t("hero_note.reassurance_unmeasured", { count: unmeasuredCount });
    heroAlertClass = "alert";
  }

  // Categories helper
  const getCategoryOf = (item: Evidence): string => {
    if (item.state === "unmeasured") return "unmeasured";
    if (item.collector.includes("fivem")) return "fivem";
    if (item.collector.includes("firmware") || item.collector.includes("driver")) return "hardware";
    if (item.collector.includes("startup")) return "startup";
    if (
      item.collector.includes("powershell") ||
      item.collector.includes("bam") ||
      item.collector.includes("pca")
    )
      return "script";
    return "other";
  };

  const countForCategory = (cat: string): number => {
    if (cat === "all") return foundItems.length + unmeasuredItems.length;
    return view.evidence.filter(
      (e) => (e.state === "found" || e.state === "unmeasured") && getCategoryOf(e) === cat,
    ).length;
  };

  const toggleRow = (ruleId: string) => {
    setOpenRows((prev) => ({ ...prev, [ruleId]: !prev[ruleId] }));
  };

  // Filter items
  const query = searchQuery.trim().toLowerCase();
  const displayItems = view.evidence.filter((item) => {
    if (item.state !== "found" && item.state !== "unmeasured") return false;
    const cat = getCategoryOf(item);
    if (currentCategory !== "all" && cat !== currentCategory) return false;
    if (!query) return true;

    const text = texts[item.rule_id];
    if (item.rule_id.toLowerCase().includes(query)) return true;
    if (text?.title?.toLowerCase().includes(query)) return true;
    if (text?.description?.toLowerCase().includes(query)) return true;
    return false;
  });

  return (
    <div className="human-summary-container">
      {/* Hero Reassurance Banner */}
      <div className={`hero-note ${heroAlertClass}`}>
        <div className="hero-title">
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#0869b0"
            strokeWidth="2.5"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="16" x2="12" y2="12" />
            <line x1="12" y1="8" x2="12.01" y2="8" />
          </svg>
          <span>{t("hero_note.title")}</span>
        </div>
        <p className="hero-desc">{heroDesc}</p>
      </div>

      {/* Interactive Visual Horizon Timeline */}
      <HorizonTimeline
        view={view}
        header={header}
        onStepClick={(stepIndex) => {
          if (stepIndex === 0 && hasTamper) {
            setCurrentCategory("script");
          } else if (stepIndex === 1) {
            setCurrentCategory("hardware");
          } else if (stepIndex === 2) {
            setCurrentCategory("fivem");
          } else {
            setCurrentCategory("all");
          }
        }}
      />

      {/* Tally Stats Cards */}
      <div className="tally">
        <button
          type="button"
          className="tally-item tally-found"
          onClick={() => setCurrentCategory("all")}
        >
          <div className="count">
            <span className="tally-mark">■</span>
            <span>{view.listed.found}</span>
          </div>
          <div className="label">{t("summary.found")}</div>
        </button>

        <button type="button" className="tally-item tally-not_found" onClick={onSwitchToTechnical}>
          <div className="count">
            <span className="tally-mark">○</span>
            <span>{view.listed.not_found}</span>
          </div>
          <div className="label">{t("summary.not_found")}</div>
        </button>

        <button
          type="button"
          className="tally-item tally-unmeasured"
          onClick={() => setCurrentCategory("unmeasured")}
        >
          <div className="count">
            <span className="tally-mark">◌</span>
            <span>{view.listed.unmeasured}</span>
          </div>
          <div className="label">{t("summary.unmeasured")}</div>
        </button>
      </div>

      {/* 3 Quick Glance Focus Cards */}
      <div className="glance-grid">
        {/* Card 1: FiveM Play */}
        <div className="glance-card">
          <div className="glance-head">
            <span className="glance-tag">
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#0869b0"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <rect x="2" y="6" width="20" height="12" rx="2" />
                <circle cx="6" cy="12" r="1" />
                <circle cx="10" cy="12" r="1" />
                <line x1="15" y1="11" x2="19" y2="11" />
                <line x1="17" y1="9" x2="17" y2="13" />
              </svg>
              <span>{t("glance.fivem_title")}</span>
            </span>
            <span className="glance-badge badge-blue">FiveM</span>
          </div>
          {(() => {
            const sessionStmt = (view.cross_source ?? []).find((cs) => cs.kind === "session");
            const recordsStmt = (view.cross_source ?? []).find(
              (cs) => cs.kind === "fivem_and_records",
            );
            let val = t("glance.fivem_none_text");
            let desc = t("glance.fivem_none_text");
            if (sessionStmt && sessionStmt.session === "known") {
              if (sessionStmt.before_scan) {
                val = `${sessionStmt.before_scan.amount} ${t(`session.duration.${sessionStmt.before_scan.unit}`, { count: sessionStmt.before_scan.amount })}`;
              }
              desc = `FiveM ${sessionStmt.edition === "enhanced" ? "Enhanced" : "Legacy"}`;
            } else if (recordsStmt) {
              if (recordsStmt.fivem.folders_days_before !== undefined) {
                val = `${recordsStmt.fivem.folders_days_before}d ago`;
              } else {
                val = t("strength.presence");
              }
              desc = `FiveM (${recordsStmt.fivem.editions.join(", ") || "Active"})`;
            }
            return (
              <>
                <div className="glance-value">{val}</div>
                <div className="glance-text">{desc}</div>
              </>
            );
          })()}
        </div>

        {/* Card 2: History Continuity */}
        <div className="glance-card">
          <div className="glance-head">
            <span className="glance-tag">
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#4f5d77"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <span>{t("glance.history_title")}</span>
            </span>
            <span className={`glance-badge ${hasTamper ? "badge-red" : "badge-gray"}`}>
              {hasTamper ? t("glance.history_tamper_badge") : t("state.not_found")}
            </span>
          </div>
          <div className="glance-value">
            {hasTamper ? t("glance.history_tamper_badge") : t("state.not_found")}
          </div>
          <div className="glance-text">
            {hasTamper ? t("glance.history_tamper_desc") : t("glance.history_not_found_desc")}
          </div>
        </div>

        {/* Card 3: Findings Overview */}
        <div className="glance-card">
          <div className="glance-head">
            <span className="glance-tag">
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#a64b00"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <span>{t("glance.obs_title")}</span>
            </span>
            {hasTamper && (
              <span className="glance-badge badge-red">{t("glance.obs_tamper_badge")}</span>
            )}
          </div>
          <div className="glance-value">
            {foundItems.length} {t("state.found")}
          </div>
          <div className="glance-text">
            {hasTamper
              ? t("glance.obs_tamper_desc")
              : unmeasuredCount > 5
                ? t("glance.obs_unmeasured_desc")
                : t("glance.obs_found_desc")}
          </div>
        </div>
      </div>

      {/* Findings Section Header & Toolbar */}
      <div className="section-title">
        <span>{t("human_findings.section_title")}</span>
        <span className="match-stat">
          {query || currentCategory !== "all"
            ? t("human_findings.match_stat", {
                visible: displayItems.length,
                total: foundItems.length + unmeasuredItems.length,
              })
            : t("human_findings.match_stat_all", { total: displayItems.length })}
        </span>
      </div>

      <div className="findings-toolbar">
        {/* Category Chips */}
        <div className="filter-chips">
          <button
            type="button"
            className={`chip ${currentCategory === "all" ? "active" : ""}`}
            onClick={() => setCurrentCategory("all")}
          >
            {t("human_findings.chip_all")}{" "}
            <span className="chip-count">{countForCategory("all")}</span>
          </button>
          {countForCategory("hardware") > 0 && (
            <button
              type="button"
              className={`chip ${currentCategory === "hardware" ? "active" : ""}`}
              onClick={() => setCurrentCategory("hardware")}
            >
              {t("human_findings.chip_hardware")}{" "}
              <span className="chip-count">{countForCategory("hardware")}</span>
            </button>
          )}
          {countForCategory("startup") > 0 && (
            <button
              type="button"
              className={`chip ${currentCategory === "startup" ? "active" : ""}`}
              onClick={() => setCurrentCategory("startup")}
            >
              {t("human_findings.chip_startup")}{" "}
              <span className="chip-count">{countForCategory("startup")}</span>
            </button>
          )}
          {countForCategory("script") > 0 && (
            <button
              type="button"
              className={`chip ${currentCategory === "script" ? "active" : ""}`}
              onClick={() => setCurrentCategory("script")}
            >
              {t("human_findings.chip_script")}{" "}
              <span className="chip-count">{countForCategory("script")}</span>
            </button>
          )}
          {countForCategory("fivem") > 0 && (
            <button
              type="button"
              className={`chip ${currentCategory === "fivem" ? "active" : ""}`}
              onClick={() => setCurrentCategory("fivem")}
            >
              {t("human_findings.chip_fivem")}{" "}
              <span className="chip-count">{countForCategory("fivem")}</span>
            </button>
          )}
          {countForCategory("unmeasured") > 0 && (
            <button
              type="button"
              className={`chip ${currentCategory === "unmeasured" ? "active" : ""}`}
              onClick={() => setCurrentCategory("unmeasured")}
            >
              {t("human_findings.chip_unmeasured")}{" "}
              <span className="chip-count">{countForCategory("unmeasured")}</span>
            </button>
          )}
        </div>

        {/* Quick Search */}
        <div className="search-box-wrap">
          <svg
            className="search-icon"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="search"
            className="search-input"
            placeholder={t("human_findings.search_placeholder")}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Findings Accordion List */}
      <div className="finding-group">
        {displayItems.map((item) => {
          const text = texts[item.rule_id];
          const isTamper = item.strength === "tamper" && item.state === "found";
          const isUnmeasured = item.state === "unmeasured";
          const isOpen = Boolean(openRows[item.rule_id]);
          const reasons = isUnmeasured
            ? [t(`reason.${item.reason}`)]
            : text?.falsepositives && text.falsepositives.length > 0
              ? text.falsepositives
              : [text?.description || item.rule_id];

          return (
            <div
              key={item.rule_id}
              className={`finding-row ${isTamper ? "tamper" : ""} ${isUnmeasured ? "unmeasured" : ""}`}
            >
              <button
                type="button"
                className="finding-head"
                onClick={() => toggleRow(item.rule_id)}
              >
                <div className="finding-head-left">
                  <span className="finding-indicator">{isUnmeasured ? "◌" : "■"}</span>
                  <div className="finding-title-wrap">
                    <div className="finding-title">
                      <span>{text?.title ?? item.rule_id}</span>
                      <span className={`strength-pill pill-${item.strength}`}>
                        {t(`strength.${item.strength}`)}
                      </span>
                    </div>
                    {text?.description && (
                      <div className="finding-human-hint">{text.description}</div>
                    )}
                  </div>
                </div>
                <div className="toggle-arrow">
                  {isOpen ? t("human_findings.hide_causes") : t("human_findings.show_causes")}
                </div>
              </button>

              {isOpen && (
                <div className="finding-details open">
                  <div
                    className={`reassurance-card ${isTamper ? "tamper-explain" : ""} ${isUnmeasured ? "unmeasured-explain" : ""}`}
                  >
                    <strong>
                      {isTamper
                        ? t("human_findings.tamper_causes_title")
                        : isUnmeasured
                          ? t("human_findings.unmeasured_causes_title")
                          : t("human_findings.causes_title")}
                    </strong>
                    <ul>
                      {reasons.map((r) => (
                        <li key={r}>{r}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="tech-raw-tag">
                    {item.collector} / {item.rule_id}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
