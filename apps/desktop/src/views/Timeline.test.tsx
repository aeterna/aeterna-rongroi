// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// ADR 0051 and ADR 0062 section 5: the end of an edition's latest session, where BAM recorded it, is one
// timeline entry per edition. It is labelled with the session statement's own wording, never as the
// Windows start, and the scan's own times stay as they were beside it.

import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import i18n, { initI18n } from "../i18n";
import type { Timeline as TimelineData, TimelineEntry } from "../types";
import { Timeline } from "./Timeline";

/** A session-end entry as the core serialises it: BAM's end for one edition. */
function sessionEnd(edition: string, at: string): TimelineEntry {
  return {
    at,
    collector: "bam",
    field: "last_run",
    place: null,
    subject: null,
    source: { kind: "session_end", edition },
  };
}

/** One of the scan's own times, as an anchor. */
function anchor(field: string, at: string): TimelineEntry {
  return { at, collector: null, field, place: null, subject: null, source: { kind: "anchor" } };
}

function timelineOf(entries: TimelineEntry[]): TimelineData {
  return { entries, bands: [], unmeasured: [] };
}

/** The text of each shown time, in the order the timeline shows them. */
function shownEntries(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll(".entries li")).map((item) => item.textContent ?? "");
}

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  await i18n.changeLanguage("en");
});

afterEach(() => {
  cleanup();
});

describe("Timeline session end", () => {
  it("shows a session end with its own label, not the Windows started label", () => {
    const { container } = render(
      <Timeline timeline={timelineOf([sessionEnd("legacy", "2026-01-10T10:30:00Z")])} texts={{}} />,
    );
    const entries = shownEntries(container);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toContain("ended 2026-01-10T10:30:00Z (BAM)");
    expect(entries[0]).not.toContain("Windows started");
    expect(entries[0]).not.toContain("no rule matched this");
  });

  it("keeps the scan's own times as they were beside a session end", () => {
    const { container } = render(
      <Timeline
        timeline={timelineOf([
          anchor("boot_time", "2026-01-09T08:00:00Z"),
          sessionEnd("legacy", "2026-01-10T10:30:00Z"),
          anchor("generated_at", "2026-01-10T12:00:00Z"),
        ])}
        texts={{}}
      />,
    );
    const entries = shownEntries(container);
    expect(entries).toHaveLength(3);
    expect(entries[0]).toContain("Windows started");
    expect(entries[1]).toContain("ended 2026-01-10T10:30:00Z (BAM)");
    expect(entries[1]).not.toContain("Windows started");
    expect(entries[2]).toContain("This scan ran");
  });

  it("shows each edition's session end as its own entry", () => {
    const { container } = render(
      <Timeline
        timeline={timelineOf([
          sessionEnd("legacy", "2026-01-10T10:30:00Z"),
          sessionEnd("enhanced", "2026-01-10T11:20:00Z"),
        ])}
        texts={{}}
      />,
    );
    const entries = shownEntries(container);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toContain("ended 2026-01-10T10:30:00Z (BAM)");
    expect(entries[1]).toContain("ended 2026-01-10T11:20:00Z (BAM)");
    // The two labels differ by edition name alone.
    expect(entries[0]).toContain("Legacy");
    expect(entries[1]).toContain("Enhanced");
    expect(entries[0]).not.toContain("Enhanced");
    expect(entries[1]).not.toContain("Legacy");
  });
});
