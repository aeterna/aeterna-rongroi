# ADR 0001 — Rust workspace, Tauri 2 GUI with hardening, and a CLI

- Status: accepted
- Date: 2026-09-11

## Context

The tool runs on Windows 10 22H2 and Windows 11, reads local artifacts, must never write to the scanned
machine, and must be easy for outside contributors to extend with rules and translations. Thai text must
render correctly. The owner wants a GUI from the first milestone.

Considered: Rust + Tauri 2, C# / .NET 8, Go + Wails, and CLI-only.

## Decision

- **Rust cargo workspace** for everything that reads the machine and evaluates rules.
- **Tauri 2** (React + Vite + TypeScript) for the GUI, because WebView2 renders Thai correctly and the UI
  layer is familiar to web contributors.
- **A CLI binary** that does not use WebView2, for users who want no WebView component involved.

WebView2 is a Microsoft component with behaviour we do not fully control. Verified facts (2026-09-11):

| Fact | Source | What we do |
|---|---|---|
| The user data folder "is created on startup" | Microsoft Learn, *Manage user data folders* | Scan and freeze the report **before** creating the window; put the data folder under `%TEMP%`; use incognito; delete it after WebView2 exits |
| SmartScreen is "enabled by default" and sends data to Microsoft | Microsoft Learn, *Data and privacy in WebView2* | Tauri/wry passes `--disable-features=…msSmartScreenProtection` by default; a test fails if our browser arguments ever drop it |
| "Regardless of the Windows Diagnostic data setting, WebView2 collects required data"; crash dumps may be sent | same page | Not controllable from Tauri/wry (no crash-reporting option found in tauri-apps/wry). Disclosed in the consent screen, PRIVACY.md and README |

## Consequences

- Public wording separates "our code sends nothing" from "the GUI uses WebView2" (ADR 0003).
- The Linux CI job cannot build the Tauri crate without webkit2gtk, so the workspace's `default-members`
  exclude it; the Windows job builds it.
- Two front ends share one scan function, so results cannot differ between them.
