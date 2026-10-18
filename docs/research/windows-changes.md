# Windows changes that may touch a collector

The monthly read of ADR 0075 §3. One section per month, newest first. Each item was checked by a maintainer
against the Microsoft page it links; an item marked *inferred* is our reading of its effect, not something
the page says. "Nothing" means the read looked and found nothing — not that nothing changed.

Areas read each month: event log channels and providers, Defender and Code Integrity, HVCI, the vulnerable
driver blocklist, Secure Boot and TPM, PCA, Prefetch, BAM, the USN journal, autostart places, hosts / proxy /
firewall store, PowerShell logging, device enumeration and Fast Startup, OS identification values.

## 2026-10 (window 2026-09-01 to 2026-10-18)

Read by a read-only helper with web access; checked by Claude Code - Claude Opus 5.5 on 2026-10-18.

**Builds in the window.** Windows 11 24H2 / 25H2 / 26H2 reached 26100.9711 / 26200.9711 / 26300.9711 with
[KB5127648](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/10/kb5127648-windows-11-24h2-25h2-26h2-security-update)
(2026-10-13). Windows Server 2025 reached 26100.33650
([KB5126646](https://support.microsoft.com/en-us/servicing/os/windows-server/2026/10/kb5126646-windows-server-2025-security-update)).
Not checked by the maintainer: the Server 2022 and Windows 10 build numbers.

| Change | Collector | What we do |
|---|---|---|
| Windows 11 26H2 exists as build 26300, installed as an enablement package on 24H2/25H2 ([26H2 update history](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/windows-11-version-26h2-update-history)). The ADR 0069 lab machine's build 26300 is this version (*inferred* from the build number). | `os_image` | Nothing to change: `os_image` reports `DisplayVersion` as Windows writes it. ADR 0056's measured values are from 25H2; a 26H2 reading comes from the lab machine or the watch. |
| Windows 11 24H2 Home and Pro reached end of updates with KB5127648 (same KB page). | `os_image` | None. A Home/Pro PC still on 26100 after October is out of support; the tool reports, it does not judge. |
| From October 2026, quality updates start turning on memory integrity, and on some devices VBS, on more eligible devices ([message center, 2026-09-01](https://learn.microsoft.com/en-us/windows/release-health/windows-message-center)). | `posture` (HVCI) | None. More PCs will read memory integrity on, so the posture row for it off becomes rarer (*inferred*). |
| Secure Boot certificate updates continue; some devices get one extra restart during installation (message center, 2026-10-13; KB5127648). | `windows_start`, `posture` | None. The extra restart is one more start on the timeline (*inferred*). |
| ReFS auditing and policy controls added for externally attached storage (KB5127648). | `evtx` | None. Rules match by provider, channel and event id; new audit events appear as unmatched groups (*inferred*). |
| Administrator protection is on by default in the 24H2 / 25H2 / 26H2 **security baselines** (KB5127648), not on consumer PCs. | every elevated read | Watch for it: an elevated scan on a PC with that baseline may run under a different admin token (*inferred*, not measured). |
| Defender platform 4.18.26090.9 (2026-10-12) renamed a PowerShell property, `ControlledConfigurationState` to `ConfigurationProtection` ([release notes](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-releases)). | none | None. No collector uses PowerShell; `windows.yml` reads other `Get-MpComputerStatus` properties (checked). |
| Microsoft Windows Production PCA 2011 expires 2026-10-19; Microsoft moves code signing to a new hierarchy ([next-generation code signing](https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/08/next-generation-code-signing)). | `driver_service`, `autostart`, `fivem_dir` signature checks | Not checked by the maintainer. No rule's `allow` pins a Microsoft certificate (`certificate-pins` covers FiveM's). Whether offline `WinVerifyTrust` (ADR 0035) treats files signed under the new hierarchy the same way is unverified; the watch will show a changed state on the runners first. |

**Nothing found** for: Kernel-PnP and CAPI2 channels, log clearing events, Defender exclusion storage and events
1116/1117/5001, TPM, Kernel DMA protection, PCA, Prefetch, BAM, the USN journal, Amcache, scheduled tasks,
services, Run keys, hosts / proxy / firewall store, PowerShell script block logging and PSReadLine, CfgMgr32,
`setupapi.dev.log`, Fast Startup, `EnumDeviceDrivers`, ToolHelp. The read covered release notes, not each API's
documentation.

**Could not verify:** whether the vulnerable driver blocklist changed in the window (its page was updated
2026-10-08 with no stated change).
