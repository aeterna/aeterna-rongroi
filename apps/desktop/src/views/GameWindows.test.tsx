// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// Component tests for GameWindowsSection, including before-the-scan device counts (ADR 0096).

import { render, screen } from "@testing-library/react";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import i18n, { initI18n } from "../i18n";
import type { GameWindows, ReportView } from "../types";
import { GameWindowsSection } from "./GameWindows";

function mockReportView(gameWindows?: GameWindows): ReportView {
  return {
    mode: "self",
    header: {
      schema_version: 1,
      provenance: { official: false, version: "0.0.0-test", commit: null, exe_sha256: null },
      rules_bundle: { schema_version: 1, sha256: "0".repeat(64), rule_count: 0 },
      platform: "windows",
      os_build: null,
      elevated: false,
      generated_at: "2026-01-10T12:00:00Z",
      boot_time: { state: "unmeasured", reason: "not_attempted" },
    },
    evidence: [],
    own_traces: [],
    unmatched: [],
    scope: { not_admin: 0, not_attempted: 0 },
    listed: { found: 0, not_found: 0, unmeasured: 0 },
    timeline: { entries: [], bands: [], unmeasured: [] },
    collector_order: [],
    game_windows: gameWindows,
    hidden: { not_found: 0, unmeasured_expected: 0, unmeasured_unexpected: 0, unmatched: 0 },
  };
}

function mockGameWindows(overrides?: Partial<GameWindows>): GameWindows {
  return {
    sessions: [
      {
        edition: "legacy",
        start: "2026-10-22T20:00:00Z",
        end: "2026-10-22T21:00:00Z",
        latest: true,
      },
    ],
    candidates: [],
    counts: { before: 0, during: 0, after: 0, before_scan: 0 },
    ...overrides,
  };
}

describe("GameWindowsSection before_scan_devices", () => {
  beforeAll(async () => {
    await initI18n("en");
  });

  beforeEach(async () => {
    await i18n.changeLanguage("en");
  });

  it("does not render before_scan device line when before_scan_devices is undefined", () => {
    const view = mockReportView(mockGameWindows());
    const { container } = render(<GameWindowsSection view={view} mode="self" />);
    expect(container.textContent).not.toContain("before this scan:");
  });

  it("does not render before_scan device line when all counts are zero", () => {
    const view = mockReportView(
      mockGameWindows({
        before_scan_devices: {
          removed: {
            pci_device: 0,
            hid_device: 0,
            usb_device: 0,
            display_device: 0,
            bluetooth_device: 0,
          },
          windows_starts: 0,
        },
      }),
    );
    const { container } = render(<GameWindowsSection view={view} mode="self" />);
    expect(container.textContent).not.toContain("before this scan:");
  });

  it("renders before_scan device line when removal count or windows_starts is above zero", () => {
    const view = mockReportView(
      mockGameWindows({
        before_scan_devices: {
          removed: {
            pci_device: 1,
            hid_device: 0,
            usb_device: 0,
            display_device: 0,
            bluetooth_device: 0,
          },
          windows_starts: 2,
        },
      }),
    );
    render(<GameWindowsSection view={view} mode="self" />);
    expect(screen.getByText(/before this scan:/)).toBeInTheDocument();
    expect(screen.getByText(/1 PCI devices recorded as removed/)).toBeInTheDocument();
    expect(screen.getByText(/2 starts of Windows/)).toBeInTheDocument();
  });

  it("renders before_scan device line in Thai when language is th", async () => {
    await i18n.changeLanguage("th");
    const view = mockReportView(
      mockGameWindows({
        before_scan_devices: {
          removed: {
            pci_device: 1,
            hid_device: 0,
            usb_device: 2,
            display_device: 0,
            bluetooth_device: 0,
          },
          windows_starts: 1,
        },
      }),
    );
    render(<GameWindowsSection view={view} mode="self" />);
    expect(screen.getByText(/ก่อนสแกน:/)).toBeInTheDocument();
    expect(screen.getByText(/อุปกรณ์ PCI บันทึกว่าถูกถอดออก 1 รายการ/)).toBeInTheDocument();
    expect(screen.getByText(/อุปกรณ์ USB บันทึกว่าถูกถอดออก 2 รายการ/)).toBeInTheDocument();
    expect(screen.getByText(/Windows เริ่มทำงาน 1 ครั้ง/)).toBeInTheDocument();
  });
});
