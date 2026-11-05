// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// E3: a scroll-progress line and group dots for the technical view. Both show position, never a
// state: the line is decoration and the dots use the app's neutral blue, not found/not_found colours.

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { EvidenceGroup } from "../grouping";
import { motionReduced } from "../motion";
import "./ReportProgress.css";

/** The id Report.tsx gives a group's `h3` and the matching `aria-labelledby`. */
function headingId(collector: string): string {
  return `group-${collector}`;
}

/** Reads the motion preference; a missing matchMedia (tests, jsdom) is no request, never a throw. */
function prefersReducedMotion(): boolean {
  return motionReduced();
}

interface Props {
  /** The collector groups the technical view is rendering, in order (Report.tsx's own list). */
  groups: EvidenceGroup[];
}

/** The technical view's scroll position: the line under the header and the group dots. */
export function ReportProgress({ groups }: Props) {
  const { t, i18n } = useTranslation("report");
  const lineRef = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState<string | null>(null);
  const label = t("progress.label", {
    defaultValue: i18n.language.startsWith("th") ? "ส่วนของรายงาน" : "Report sections",
  });

  useEffect(() => {
    let frame = 0;

    const measure = () => {
      frame = 0;
      const line = lineRef.current;
      // The header wraps in a narrow window, so its measured bottom keeps the line clear of it.
      const header = document.querySelector(".top");
      if (line && header) {
        line.style.top = `${Math.round(header.getBoundingClientRect().bottom + 2)}px`;
      }
      const scrollHeight = Math.max(
        document.documentElement.scrollHeight,
        document.body.scrollHeight,
      );
      const maxScroll = scrollHeight - window.innerHeight;
      const progress = maxScroll > 0 ? Math.min(Math.max(window.scrollY / maxScroll, 0), 1) : 0;
      if (line) line.style.transform = `scaleX(${progress})`;

      // The last group whose heading has passed 40 % of the viewport is the one being read.
      const marker = window.innerHeight * 0.4;
      let current: string | null = null;
      for (const group of groups) {
        const heading = document.getElementById(headingId(group.collector));
        if (heading && heading.getBoundingClientRect().top <= marker) current = group.collector;
      }
      setActive(current);
    };

    // Scroll events can arrive faster than a frame; at most one measure runs per frame.
    const onScroll = () => {
      if (frame !== 0) return;
      frame = window.requestAnimationFrame(measure);
    };

    // The first read is immediate so the line is right before the first scroll arrives.
    measure();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    return () => {
      if (frame !== 0) window.cancelAnimationFrame(frame);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
  }, [groups]);

  function goTo(collector: string): void {
    const heading = document.getElementById(headingId(collector));
    if (!heading) return;
    if (typeof heading.scrollIntoView === "function") {
      const behavior = prefersReducedMotion() ? "auto" : "smooth";
      heading.scrollIntoView({ behavior, block: "start" });
    }
    // The heading already has tabIndex -1, so focus lands on the group rather than on the body.
    heading.focus({ preventScroll: true });
  }

  return (
    <>
      {/* Fixed, not sticky: a sticky line inside the report grid would take layout space and stop at
          the content column. Fixed leaves the page layout untouched and sits below the header. */}
      <div ref={lineRef} className="report-progress-line" aria-hidden="true" />
      {groups.length >= 2 && (
        <nav className="report-progress-dots" aria-label={label}>
          <ol>
            {groups.map((group) => (
              <li key={group.collector}>
                <a
                  href={`#${headingId(group.collector)}`}
                  className="report-progress-dot"
                  aria-current={active === group.collector ? "true" : undefined}
                  onClick={(event) => {
                    event.preventDefault();
                    goTo(group.collector);
                  }}
                >
                  <span className="visually-hidden">
                    {t(`collector.${group.collector}`, { defaultValue: group.collector })}
                  </span>
                </a>
              </li>
            ))}
          </ol>
        </nav>
      )}
    </>
  );
}
