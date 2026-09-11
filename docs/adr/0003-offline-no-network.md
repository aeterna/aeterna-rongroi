# ADR 0003 — Offline: no network code, and honest wording about it

- Status: accepted
- Date: 2026-09-11

## Context

"Nothing leaves your PC" is the main reason a player would agree to run this tool. Research found that
Cfx.re staff have advised players to refuse PC-check software, so the claim has to be both true and
checkable. The GUI's WebView2 runtime is a Microsoft component with its own diagnostics (ADR 0001).

## Decision

- No network code in our code, enforced by CI:
  - `cargo deny` bans HTTP, socket and WebSocket crates and the Tauri HTTP, updater, WebSocket and upload plugins
  - clippy `disallowed-types` bans `std::net` sockets
  - ESLint bans `fetch`, `XMLHttpRequest`, `WebSocket` and `EventSource` in the UI
  - the GUI's content-security policy allows no network connections
- No auto-update. New versions and new rules are downloaded by the user from GitHub Releases.
- Public wording, used verbatim in README, PRIVACY.md and the consent screen:
  *"aeterna-rongroi's own code sends nothing. The GUI uses Microsoft WebView2, a Windows component that may
  send Windows diagnostic data according to your Windows settings. The CLI version does not use WebView2."*

## Consequences

- Feature bans on crates that Tauri itself uses (for example tokio's `net`) are added only after
  `cargo tree -e features` shows they are not already required; otherwise the ban would break the build
  without adding safety.
- Anyone can verify the claim by reading `deny.toml`, `clippy.toml`, the ESLint config and the CSP.
