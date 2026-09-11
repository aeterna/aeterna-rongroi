# 01 — FiveM anti-cheat landscape (2026-09-11)

## Summary

- Nearly every FiveM anti-cheat is a **server resource** (Lua client + server scripts) with a web panel.
  No FiveM anti-cheat with a kernel driver was found. One product advertises an external Windows client.
- **No independent audit of detection rates was found.** A vendor-neutral comparison site states that
  published detection percentages cannot be verified
  ([FiveMonitor](https://fivemonitor.com/en/guides/best-fivem-anticheat-2026)).
- Server-side logic sees the *effects* of injected menus (impossible health, teleports, spawned entities)
  but cannot see external ESP/aimbot programs or DMA hardware.
- Cfx.re's own protections (the client-side "adhesive" component and server convars) target injection
  and exploitable network events, not read-only external cheats.

## Commercial products (as described publicly)

| Product | Architecture | Notes |
|---|---|---|
| FiveGuard | resource + panel | anti-aimbot, "AI" detection, trust score (vendor claim); third parties report its source leaked |
| WaveShield | resource + panel | claims "99.9% detection" and 15,000+ servers (vendor claim, unverified per FiveMonitor) |
| Electron | resource | session replay, OCR menu detection (vendor claim) |
| FiniAC | resource + dashboard | global cross-server bans; a 2024 Cfx forum thread criticised global ban lists ([thread](https://forum.cfx.re/t/fini-ac-breaking-tos/5252145)) |
| Reaper | resource ("LUA based") | names specific executors it detects (vendor claim) |
| Raven | resource | claims DMA detection without describing a method (vendor claim) |
| Fiveuxe | resource, global ban network | a competitor notes one false positive then affects every server in the network |
| Atomic Shield | external Windows application | the only external client found; details from search snippets only |

Prices seen ranged from roughly $20/month to €250 lifetime.

## Open-source FiveM anti-cheats

| Repository | License | Architecture | Impression |
|---|---|---|---|
| [FIREAC](https://github.com/AmirrezaJaberi/FIREAC) | AGPL-3.0 | Lua client + server | most stars (234); client-side checks trust the client |
| [Icarus](https://github.com/EinS4ckZwiebeln/IcarusAdvancedAnticheat) | GPL-3.0 | server-only TypeScript, OneSync | closest to a server-authoritative design |
| [Valkyrie](https://github.com/NotSomething0/Valkyrie) | GPL-3.0 | server-only Lua | README explains why client-side tricks are easy to bypass |
| [FiveProtect](https://github.com/coazy/FiveProtect) | source-available, **not** open source | Rust companion + scanner + backend | best design reference for posture attestation; paused |

Non-FiveM references: [UltimateAntiCheat](https://github.com/AlSch092/UltimateAntiCheat) (AGPL-3.0, user-mode,
educational) and [donnaskiez/ac](https://github.com/donnaskiez/ac) (AGPL-3.0, kernel-mode).

Several high-star search results were advertisements for paid products, and many repositories had no license.

## Thai community

Evidence was thin; treat as low confidence.

- A launcher market exists (for example KC Launcher, advertised at 400 THB) that forces joining through the
  launcher and blocks known cheat files (vendor claim).
- A 2021 Cfx forum thread says Cfx.re blocks custom server launchers
  ([thread](https://forum.cfx.re/t/custom-server-launchers/2619410)); current status not verified.
- On Pantip, players expressed distrust of server anti-cheats and paid appeals
  ([thread](https://pantip.com/topic/41428048)).
- Cheat rental is advertised openly in Thai; unban services are advertised on social media (not linked).

## Cfx.re platform rules

- The Creator Platform License Agreement (10 Sep 2026 version,
  [PDF](https://static.cfx.re/platform-license-agreement-10-sept-2026.pdf)) has **no clause** on anti-cheat,
  required third-party software, launchers or screenshots. §4 requires server admins to follow data-protection law.
- A December 2025 forum question asking whether servers may require third-party anti-cheat software got no
  staff answer ([thread](https://forum.cfx.re/t/clarification-regarding-requiring-third-party-anti-cheat-software-for-server-access/5373784)).
- The resource FAQ allows anti-cheat resources and discourages global ban lists
  ([docs](https://docs.fivem.net/docs/support/resource-faq/)).
- Server convars such as `sv_pureLevel`, `sv_entityLockdown` and `sv_filterRequestControl` close common
  exploit paths ([docs](https://docs.fivem.net/docs/server-manual/server-commands/)).

## What each architecture can realistically see

| Cheat class | Server-only | Lua client resource | External user-mode client | Kernel / attestation |
|---|---|---|---|---|
| Injected menus / Lua executors | effects only | partial, inside the environment the cheat controls | module / handle scans | stronger |
| External ESP / aimbot | aimbot statistics only | no | partial (handles, overlays) | better |
| DMA (PCIe device + second PC) | behaviour only | no | no | partial, via IOMMU |
| HWID spoofers | token correlation | no | weak | TPM-backed identity is harder to spoof |

## What this meant for aeterna-rongroi

- Do not rely on secret client-side checks: open code is readable, and closed products leak.
- Be honest about limits in a published matrix; the market has no independent verification.
- Keep any client component opt-in, consent-based and privacy-minimal.
- Do not build global ban sharing.
- Use a copyleft license.
