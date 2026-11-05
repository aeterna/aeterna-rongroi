// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// The Ctrl K / Cmd K palette jumps to one of the report's own evidence rows: no verdict or ranking.

import { type KeyboardEvent as KeyEvent, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Evidence, RuleText } from "../types";
import "./CommandPalette.css";

const INPUT_ID = "command-palette-input";
const LISTBOX_ID = "command-palette-listbox";

interface Props {
  open: boolean;
  evidence: Evidence[];
  texts: Record<string, RuleText>;
  onClose: () => void;
  onPick: (item: Evidence) => void;
}

/** The search rule shared by the toolbar search and the palette: no other field and no ranking. */
export function evidenceMatches(
  item: Evidence,
  text: RuleText | undefined,
  rawQuery: string,
): boolean {
  const query = rawQuery.trim().toLowerCase();
  if (!query) return true;
  if (item.rule_id.toLowerCase().includes(query)) return true;
  if (item.collector.toLowerCase().includes(query)) return true;
  if (text?.title?.toLowerCase().includes(query)) return true;
  if (text?.description?.toLowerCase().includes(query)) return true;
  return (
    item.state === "found" &&
    item.observations.some((obs) => JSON.stringify(obs.fields).toLowerCase().includes(query))
  );
}

function stateKeyOf(item: Evidence): string {
  if (item.state !== "unmeasured") return item.state;
  return item.expected ? "unmeasured_expected" : "unmeasured_unexpected";
}

export function CommandPalette({ open, evidence, texts, onClose, onPick }: Props) {
  const { t } = useTranslation("report");
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);
  const picked = useRef(false);

  const matching = evidence.filter((item) => evidenceMatches(item, texts[item.rule_id], query));
  const options = matching.slice(0, 8);
  const activeIndex = options.length === 0 ? -1 : Math.min(active, options.length - 1);
  const activeOption = options[activeIndex];
  const activeId = activeOption ? `palette-option-${activeOption.rule_id}` : undefined;

  useEffect(() => {
    if (!open) return;
    previousFocus.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    picked.current = false;
    setQuery("");
    setActive(0);
    inputRef.current?.focus();
  }, [open]);

  // Esc closes through the parent; every other close is a pick, which focuses the report list.
  useEffect(() => {
    if (open) return;
    if (picked.current) {
      picked.current = false;
      return;
    }
    const target = previousFocus.current;
    if (target?.isConnected) target.focus();
  }, [open]);

  function onInputKeyDown(event: KeyEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      if (options.length === 0) return;
      event.preventDefault();
      const delta = event.key === "ArrowDown" ? 1 : -1;
      setActive(
        (current) =>
          (Math.min(current, options.length - 1) + delta + options.length) % options.length,
      );
      return;
    }
    if (event.key !== "Enter") return;
    const item = options[activeIndex];
    if (!item) return;
    event.preventDefault();
    picked.current = true;
    onPick(item);
  }

  function onDialogKeyDown(event: KeyEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key !== "Tab") return;
    // The input is the dialog's only tab stop; the options are reached with the arrow keys.
    event.preventDefault();
    inputRef.current?.focus();
  }

  if (!open) return null;

  return (
    <div className="palette-backdrop">
      <div
        className="palette-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={t("palette.label")}
        onKeyDown={onDialogKeyDown}
      >
        <label className="muted" htmlFor={INPUT_ID}>
          {t("palette.input_label")}
        </label>
        <input
          ref={inputRef}
          id={INPUT_ID}
          className="search-input"
          type="text"
          role="combobox"
          tabIndex={0}
          aria-expanded="true"
          aria-controls={LISTBOX_ID}
          aria-autocomplete="list"
          aria-activedescendant={activeId}
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActive(0);
          }}
          onKeyDown={onInputKeyDown}
        />
        <div
          role="listbox"
          id={LISTBOX_ID}
          className="palette-list"
          aria-label={t("palette.list_label")}
        >
          {options.map((item, index) => (
            <button
              key={item.rule_id}
              id={`palette-option-${item.rule_id}`}
              type="button"
              role="option"
              aria-selected={index === activeIndex}
              tabIndex={-1}
              className={`palette-option${index === activeIndex ? " active" : ""}`}
              onClick={() => {
                picked.current = true;
                onPick(item);
              }}
            >
              <span className={`mark mark-${item.state}`} aria-hidden="true" />
              <span>{texts[item.rule_id]?.title ?? item.rule_id}</span>
              <span className="muted">{t(`state.${stateKeyOf(item)}`)}</span>
            </button>
          ))}
        </div>
        {options.length === 0 && <p className="muted">{t("palette.empty")}</p>}
        <p className="palette-count palette-visually-hidden" aria-live="polite">
          {t("palette.results", { count: matching.length })}
        </p>
      </div>
    </div>
  );
}
