// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { ReportHeader, ReportView, RuleText } from "../types";

interface Props {
  view: ReportView;
  header: ReportHeader;
  texts: Record<string, RuleText>;
}

export function sanitizeAiPrompt(text: string): string {
  // Mask Windows user home directories to protect privacy: C:\Users\<Username>\ -> C:\Users\<user>\
  let sanitized = text.replace(/([A-Z]:\\Users\\)[^\\]+(\\)/gi, "$1<user>$2");
  // Mask any Machine GUIDs or SID patterns if present
  sanitized = sanitized.replace(/S-1-5-21-\d+-\d+-\d+-\d+/g, "S-1-5-21-<masked-sid>");
  return sanitized;
}

export function AiExportButton({ view, header, texts }: Props) {
  const { t, i18n } = useTranslation("report");
  const [copied, setCopied] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const handleCopy = () => {
    const isThai = i18n.language.startsWith("th");
    const foundItems = view.evidence.filter((e) => e.state === "found");
    const unmeasuredItems = view.evidence.filter((e) => e.state === "unmeasured");

    const foundSummary = foundItems
      .map((item, idx) => {
        const text = texts[item.rule_id];
        const title = text?.title ?? item.rule_id;
        const strength = item.strength;
        const obsStr = item.observations
          .map((obs) =>
            Object.entries(obs.fields)
              .map(([k, v]) => `${k}=${String(v)}`)
              .join(", "),
          )
          .join("; ");
        return `${idx + 1}. ${title} (${strength}): ${obsStr || text?.description || ""}`;
      })
      .join("\n");

    const bootTimeStr =
      header.boot_time.state === "measured"
        ? `${header.boot_time.booted_at} (${Math.round(header.boot_time.seconds_since_boot / 3600)}h ago)`
        : "Unmeasured";

    const promptRaw = isThai
      ? `ฉันต้องการให้คุณช่วยวิเคราะห์รายงานการตรวจเครื่อง (PC Forensics / FiveM Check) จากโปรแกรม aeterna-rongroi v${header.provenance.version}
โปรดวิเคราะห์ข้อเท็จจริงอย่างเป็นกลาง โดยอ้างอิงจากหลักฐานทางเทคนิค และแยกแยะระหว่าง "พฤติกรรมการใช้งานทั่วไป (Benign)" กับ "พฤติกรรมที่น่าสงสัย (Suspicious / Tampering)"

นี่คือข้อมูลผลการสแกนของฉัน:
--------------------------------------------------
[ข้อมูลเครื่อง & สถานะการสแกน]
- ระบบปฏิบัติการ: ${[header.platform, header.os_build].filter(Boolean).join(" ")} (${header.elevated ? "Administrator" : "Standard User"})
- เวลาบูตเครื่อง: ${bootTimeStr}
- ชุดกฎ: ${header.rules_bundle.rule_count} กฎ (พบ ${view.listed.found} ข้อ, ไม่พบ ${view.listed.not_found} ข้อ, ยังไม่ได้วัด ${view.listed.unmeasured} ข้อ)

[ข้อสังเกตที่ตรวจพบ ${foundItems.length} ข้อ]
${foundSummary || "ไม่พบข้อสังเกตใดๆ"}

[ข้อมูลขอบเขตประวัติ & FiveM]
- จำนวนรายการที่ยังไม่ได้วัด: ${unmeasuredItems.length} ข้อ
- ประวัติการเล่น FiveM และความต่อเนื่องของ Event Logs ตามรายงานบนหน้าจอ
--------------------------------------------------

คำถามที่อยากให้คุณช่วยสรุป:
1. เครื่องนี้มีแนวโน้มเป็นการใช้งานของบุคคลทั่วไป หรือมีข้อบ่งชี้ว่าดัดแปลงเกม/ใช้โปรแกรมโกง/ลบประวัติเครื่องหรือไม่?
2. ข้อสังเกตที่พบแต่ละข้อ อธิบายสาเหตุทางเทคนิคได้อย่างไรบ้าง?
3. สรุปคำแนะนำสั้นๆ 3 บรรทัด แบบกระชับและเข้าใจง่าย`
      : `Please analyze this PC Forensics / FiveM inspection report from aeterna-rongroi v${header.provenance.version}.
Provide a neutral, technical analysis distinguishing between benign everyday usage and suspicious or tampering indicators.

Inspection Report Data:
--------------------------------------------------
[Machine & Scan Context]
- OS: ${[header.platform, header.os_build].filter(Boolean).join(" ")} (${header.elevated ? "Administrator" : "Standard User"})
- Boot Time: ${bootTimeStr}
- Rules: ${header.rules_bundle.rule_count} rules (Found: ${view.listed.found}, Not Found: ${view.listed.not_found}, Unmeasured: ${view.listed.unmeasured})

[Observations Found (${foundItems.length})]
${foundSummary || "None"}

[History Horizon Context]
- Unmeasured checks: ${unmeasuredItems.length}
--------------------------------------------------

Questions:
1. Does this machine reflect ordinary user patterns, or are there indications of game tampering, cheating, or anti-forensics?
2. How can each observed finding be explained technically?
3. Provide a concise 3-line summary.`;

    const cleanPrompt = sanitizeAiPrompt(promptRaw);

    void navigator.clipboard.writeText(cleanPrompt).then(() => {
      setCopied(true);
      setToastMessage(t("ai_export.toast_message"));
      setTimeout(() => {
        setCopied(false);
      }, 3000);
      setTimeout(() => {
        setToastMessage(null);
      }, 4000);
    });
  };

  return (
    <>
      <button
        type="button"
        className={`btn-ai ${copied ? "copied" : ""}`}
        onClick={handleCopy}
        aria-label={t("ai_export.button_label")}
      >
        <svg
          width="17"
          height="17"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          {copied ? (
            <polyline points="20 6 9 17 4 12" />
          ) : (
            <>
              <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
              <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
              <line x1="12" y1="22.08" x2="12" y2="12" />
            </>
          )}
        </svg>
        <span>{copied ? t("ai_export.copied_label") : t("ai_export.button_label")}</span>
      </button>

      {toastMessage && (
        <div className="toast show" role="status" aria-live="polite">
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#34d399"
            strokeWidth="2.5"
            aria-hidden="true"
          >
            <polyline points="20 6 9 17 4 12" />
          </svg>
          <span>{toastMessage}</span>
        </div>
      )}
    </>
  );
}
