// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// E11: the Sources drawer answers "where does this result come from?" for one row. It reads only the
// Evidence and RuleText props the row already has, so SS-mode filtering in rongroi-core stays intact.

import { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import { motionReduced } from "../motion";
import type { Evidence, RuleFiles, RuleText } from "../types";
import { CodeLink } from "./CodeLink";
import "./EvidenceRow.sources.css";

/** Fired on window when a row opens its drawer, so every other row closes its own. */
const SOURCES_OPEN_EVENT = "rongroi:sources-open";

interface Props {
  item: Evidence;
  text: RuleText | undefined;
  fileBase: string | null;
  treeBase: string | null;
}

/**
 * The row's Source button and the drawer it opens. The drawer is deliberately not modal: it never
 * dims the report, never traps focus and never hides another row, so the page stays readable beside
 * it. Its content is the same rule id, collector, retention and code links the row already shows.
 */
export function SourcesButton({ item, text, fileBase, treeBase }: Props) {
  const { t } = useTranslation("report");
  const [open, setOpen] = useState(false);
  const [entered, setEntered] = useState(false);
  const restoreFocus = useRef(false);
  const openerRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const instanceId = useId();
  const headingId = `sources-heading-${instanceId.replace(/[^a-zA-Z0-9_-]/g, "")}`;

  // A CustomEvent rather than shared state keeps each row independent: opening a second drawer is
  // what closes the first, and the first must not pull focus back to its own opener on the way out.
  // The listener stays registered while the row is mounted, so a second row clicked in the same
  // event batch still closes a first drawer whose open effect has not run yet.
  useEffect(() => {
    function onAnotherOpen(event: Event) {
      if (!(event instanceof CustomEvent) || event.detail === instanceId) {
        return;
      }
      restoreFocus.current = false;
      setOpen(false);
      setEntered(false);
    }
    window.addEventListener(SOURCES_OPEN_EVENT, onAnotherOpen);
    return () => window.removeEventListener(SOURCES_OPEN_EVENT, onAnotherOpen);
  }, [instanceId]);

  // Focus moves into the drawer as it opens; Escape closes it from anywhere on the page.
  useEffect(() => {
    if (!open) {
      return;
    }
    closeRef.current?.focus();
    function onKeyDown(event: KeyboardEvent) {
      // The palette sits above this drawer; an Escape it has already handled stays its own.
      if (event.key !== "Escape" || event.defaultPrevented) {
        return;
      }
      event.preventDefault();
      restoreFocus.current = true;
      setOpen(false);
      setEntered(false);
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  // Only a close the reader asked for returns focus to the button; a drawer closed by another row
  // opening leaves focus on that row's close button.
  useEffect(() => {
    if (open || !restoreFocus.current) {
      return;
    }
    restoreFocus.current = false;
    openerRef.current?.focus();
  }, [open]);

  // The panel starts off the right edge and slides in on the next frame. Under reduced motion it is
  // already in place when it mounts, and the stylesheet has no transition to soften it.
  useEffect(() => {
    if (!open) {
      return;
    }
    if (prefersReducedMotion()) {
      setEntered(true);
      return;
    }
    const frame = window.requestAnimationFrame(() => setEntered(true));
    return () => window.cancelAnimationFrame(frame);
  }, [open]);

  function openDrawer() {
    if (open) {
      closeDrawer();
      return;
    }
    setEntered(prefersReducedMotion());
    window.dispatchEvent(new CustomEvent(SOURCES_OPEN_EVENT, { detail: instanceId }));
    setOpen(true);
  }

  function closeDrawer() {
    restoreFocus.current = true;
    setOpen(false);
    setEntered(false);
  }

  return (
    <>
      <button
        type="button"
        className="sources-button"
        ref={openerRef}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={openDrawer}
      >
        {t("sources.button", { defaultValue: "Source" })}
      </button>
      {open &&
        createPortal(
          <aside
            className="sources-panel"
            role="dialog"
            aria-modal="false"
            aria-labelledby={headingId}
            data-open={entered ? "true" : "false"}
          >
            <div className="sources-head">
              <h2 id={headingId}>{t("sources.title", { defaultValue: "Sources" })}</h2>
              <button
                type="button"
                className="sources-button sources-close"
                ref={closeRef}
                onClick={closeDrawer}
              >
                {t("sources.close", { defaultValue: "Close" })}
              </button>
            </div>
            <dl className="sources-facts">
              <dt>{t("sources.rule", { defaultValue: "Rule id" })}</dt>
              <dd>
                <code className="selectable">{item.rule_id}</code>
              </dd>
              <dt>{t("sources.collector", { defaultValue: "Collector" })}</dt>
              <dd>
                <code>{item.collector}</code>
              </dd>
              {item.state === "not_found" && (
                <>
                  <dt>{t("sources.retention", { defaultValue: "Look-back" })}</dt>
                  <dd>{text?.retention ?? item.retention}</dd>
                </>
              )}
            </dl>
            {text && <SourcesCode files={text.files} fileBase={fileBase} treeBase={treeBase} />}
          </aside>,
          document.body,
        )}
    </>
  );
}

/** Whether the platform asks for reduced motion; a missing `matchMedia` is not a reason to throw. */
function prefersReducedMotion(): boolean {
  return motionReduced();
}

/**
 * The same three repository paths and references the row's technical layer renders, through the
 * same CodeLink, so the drawer adds no field the row does not already show.
 */
function SourcesCode({
  files,
  fileBase,
  treeBase,
}: {
  files: RuleFiles;
  fileBase: string | null;
  treeBase: string | null;
}) {
  const { t } = useTranslation("report");
  const paths: [string, string, string | null][] = [
    ["layers.rule_file", files.rule, fileBase && `${fileBase}/${files.rule}`],
    ["layers.fixtures", files.fixtures, treeBase && `${treeBase}/${files.fixtures}`],
    ["layers.collector_file", files.collector, fileBase && `${fileBase}/${files.collector}`],
  ];
  const label = t("sources.code", { defaultValue: "Where this is in the code" });
  return (
    <section className="sources-code" aria-label={label}>
      <h3>{label}</h3>
      <ul>
        {paths.map(([key, path, link]) => (
          <li key={key}>
            <span className="muted">{t(key)}</span> <CodeLink text={path} copy={link} />
          </li>
        ))}
        {files.references.map((url) => (
          <li key={url}>
            <span className="muted">{t("layers.reference")}</span>{" "}
            <CodeLink text={url} copy={url} />
          </li>
        ))}
      </ul>
    </section>
  );
}
