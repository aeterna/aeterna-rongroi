// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// The Sources drawer answers "where does this result come from?" beside the report, never over it:
// it is non-modal, one row at a time, and it leaves the report's own rows readable.

import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import i18n, { initI18n } from "../i18n";
import type { Evidence, RuleText } from "../types";
import { EvidenceRow } from "./EvidenceRow";

const FOUND_RULE_ID = "3b9e1c2a-5d7f-4e8a-9c1b-2f6d8a0e4b71";
const NOT_FOUND_RULE_ID = "7c1d4e2b-8a3f-4b6c-9d0e-1a2b3c4d5e6f";

const FOUND: Evidence = {
  rule_id: FOUND_RULE_ID,
  collector: "evtx",
  strength: "tamper",
  state: "found",
  observations: [],
};

const NOT_FOUND: Evidence = {
  rule_id: NOT_FOUND_RULE_ID,
  collector: "registry",
  strength: "presence",
  state: "not_found",
  retention: "the look-back the rule states",
};

const FOUND_TEXT: RuleText = {
  title: "A check that matched",
  description: "What this check means.",
  falsepositives: [],
  retention: "the look-back a found row must not show",
  status: "stable",
  files: {
    rule: "rules/example/rule.yaml",
    fixtures: "rules/example",
    collector: "crates/rongroi-collectors/src/example.rs",
    references: [],
  },
};

const originalMatchMedia = Object.getOwnPropertyDescriptor(window, "matchMedia");

/** A complete MediaQueryList stub: the row and the drawer both subscribe to the same query. */
function installMatchMedia(matches: boolean) {
  const media = {
    matches,
    media: "(prefers-reduced-motion: reduce)",
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  };
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: vi.fn(() => media),
  });
  return media;
}

function rowFor(item: Evidence, text?: RuleText) {
  return (
    <EvidenceRow
      item={item}
      text={text}
      fileBase={null}
      treeBase={null}
      linksKnown={true}
      official={false}
      technicalAll={false}
    />
  );
}

function renderRow(item: Evidence, text?: RuleText) {
  return render(rowFor(item, text));
}

function renderRows(items: Evidence[]) {
  return render(
    <ul>
      {items.map((item) => (
        <EvidenceRow
          key={item.rule_id}
          item={item}
          text={undefined}
          fileBase={null}
          treeBase={null}
          linksKnown={true}
          official={false}
          technicalAll={false}
        />
      ))}
    </ul>,
  );
}

function rowElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>("li.row"));
}

function sourceIn(row: HTMLElement): HTMLElement {
  return within(row).getByRole("button", { name: "Source" });
}

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  if (originalMatchMedia) {
    Object.defineProperty(window, "matchMedia", originalMatchMedia);
  } else {
    Reflect.deleteProperty(window, "matchMedia");
  }
});

describe("the Sources drawer", () => {
  it("opens a non-modal dialog in the document body with the row's rule id and collector", () => {
    const { container } = renderRow(FOUND);

    fireEvent.click(screen.getByRole("button", { name: "Source" }));

    const dialog = screen.getByRole("dialog", { name: "Sources" });
    // The drawer is portalled out of the row, beside the report rather than inside it.
    expect(document.body.contains(dialog)).toBe(true);
    expect(container.contains(dialog)).toBe(false);
    // It never takes modality away from the report.
    expect(dialog.getAttribute("aria-modal")).toBe("false");
    expect(within(dialog).getByText(FOUND.rule_id)).not.toBeNull();
    expect(within(dialog).getByText(FOUND.collector)).not.toBeNull();
  });

  it("closes on Escape and returns focus to the Source button", () => {
    renderRow(NOT_FOUND);
    const source = screen.getByRole("button", { name: "Source" });

    fireEvent.click(source);
    expect(screen.getByRole("dialog", { name: "Sources" })).not.toBeNull();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(document.querySelectorAll('[role="dialog"]')).toHaveLength(0);
    expect(document.activeElement).toBe(source);
  });

  it("closes the first drawer when a second row opens its own", () => {
    const { container } = renderRows([FOUND, NOT_FOUND]);
    const rows = rowElements(container);
    expect(rows).toHaveLength(2);

    fireEvent.click(sourceIn(rows[0] as HTMLElement));
    const first = screen.getByRole("dialog", { name: "Sources" });
    expect(within(first).getByText(FOUND.rule_id)).not.toBeNull();

    fireEvent.click(sourceIn(rows[1] as HTMLElement));

    expect(document.querySelectorAll('[role="dialog"]')).toHaveLength(1);
    const remaining = screen.getByRole("dialog", { name: "Sources" });
    expect(within(remaining).getByText(NOT_FOUND.rule_id)).not.toBeNull();
    expect(within(remaining).queryByText(FOUND.rule_id)).toBeNull();
  });

  it("leaves the report's rows non-inert while a drawer is open", () => {
    const { container } = renderRows([FOUND, NOT_FOUND]);
    const rows = rowElements(container);
    expect(rows).toHaveLength(2);

    fireEvent.click(sourceIn(rows[0] as HTMLElement));

    for (const row of rowElements(container)) {
      expect(row.hasAttribute("inert")).toBe(false);
    }
    expect(container.querySelector("li.row[inert]")).toBeNull();
  });

  it("shows the panel open at once when reduced motion is requested", () => {
    installMatchMedia(true);
    renderRow(NOT_FOUND);

    fireEvent.click(screen.getByRole("button", { name: "Source" }));

    const panel = screen.getByRole("dialog", { name: "Sources" });
    expect(panel.getAttribute("data-open")).toBe("true");
  });
});

describe("the Sources drawer's facts", () => {
  it("shows the look-back for a not_found row", () => {
    renderRow(NOT_FOUND);

    fireEvent.click(screen.getByRole("button", { name: "Source" }));

    const dialog = screen.getByRole("dialog", { name: "Sources" });
    expect(within(dialog).getByText("Look-back")).not.toBeNull();
    expect(within(dialog).getByText(NOT_FOUND.retention)).not.toBeNull();
  });

  it("has no look-back entry for a found row, even when the rule text carries one", () => {
    renderRow(FOUND, FOUND_TEXT);

    fireEvent.click(screen.getByRole("button", { name: "Source" }));

    const dialog = screen.getByRole("dialog", { name: "Sources" });
    expect(within(dialog).queryByText("Look-back")).toBeNull();
    expect(within(dialog).queryByText(FOUND_TEXT.retention)).toBeNull();
  });
});
