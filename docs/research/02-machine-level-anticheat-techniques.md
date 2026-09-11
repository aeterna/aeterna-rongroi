# 02 — Machine-level anti-cheat techniques (2026-09-11)

## Architectures

| | Kernel driver | User-mode program | Server-side only |
|---|---|---|---|
| Sees | handles to the game, driver loads, boot-time state | processes, windows, modules, drivers, code-integrity flags | game state and behaviour |
| Blind to | DMA hardware unless IOMMU is enforced | anything more privileged than itself ([writeup](https://billdemirkapi.me/insecure-by-design-weaponizing-windows-against-usermode-anticheats/)) | the PC |
| Cost | Microsoft driver signing with an EV certificate ([docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)); a signed driver can be abused by attackers ([Trend Micro on mhyprot2](https://www.trendmicro.com/en_us/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver-to-kill-antivirus.html)) | code signing; SmartScreen reputation builds over time, EV no longer gives instant reputation ([docs](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)) | engineering time |

An academic study of 11 shooters (CheckMATE '24, [PDF](https://tomchothia.gitlab.io/Papers/AntiCheat2024.pdf))
found stronger client protection correlates with higher cheat prices and lower cheat uptime — but cheats
were still sold for every game.

Windows now offers `GetRuntimeAttestationReport`, a nonce-bound report of loaded drivers and code-integrity
state signed by the Secure Kernel, available to user-mode programs on machines with TPM 2.0, Secure Boot,
VBS, HVCI and IOMMU enabled ([docs](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getruntimeattestationreport)).

## User-mode signals

| Signal | Value | False-positive risk | Notes |
|---|---|---|---|
| Known-file hashes and names | medium against public cheats | low for hashes | trivial to change a file |
| Overlay windows | medium | **high** (Discord, NVIDIA, OBS) | legitimate overlays are common |
| Open handles to the game | medium | **high** (antivirus, recorders) | |
| Module signature checks | low–medium | medium (ReShade and similar) | manually mapped code does not appear |
| Loaded drivers vs vulnerable-driver lists | medium | medium | [LOLDrivers](https://www.loldrivers.io/); Microsoft's blocklist does not cover all of them |
| Test-signing / code-integrity flags | **high, cheap** | low | |
| Secure Boot / TPM / HVCI / IOMMU state | high as context | low | self-reported unless attested |
| VM / hypervisor detection | low | **very high** — VBS sets the hypervisor flag on normal PCs | |

## Proving a client is genuine

"The client says it is clean" is weak: the attacker owns the machine, and replies can be replayed or relayed
from a clean PC ([secret.club on BattlEye](https://secret.club/2020/07/06/bottleye.html)).
Server-authoritative designs — behaviour models such as Valve's VACnet
([GDC talk](https://www.gdcvault.com/play/1024994/Robocalypse-Now-Using-Deep-Learning)), not sending hidden
players' positions ([Riot on Fog of War](https://technology.riotgames.com/news/demolishing-wallhacks-valorants-fog-war)),
and FiveM OneSync culling ([docs](https://docs.fivem.net/docs/scripting-reference/onesync/)) — remove what
cheats can read.

**aeterna-rongroi is offline by owner decision**, so it does not attempt attestation. It shows evidence and
states that the result cannot prove a machine is clean.

## The open-source problem

Public detection logic helps cheat developers. Credible open projects either keep detection server-side
(e.g. [Grim](https://github.com/GrimAnticheat/Grim), which predicts physics) or open the engine and keep
signatures private. Obfuscation only buys time. aeterna-rongroi publishes everything and puts its value in
correlating robust artifacts and being honest about limits.

## Privacy and law (Thailand)

- The PDPA covers data that identifies a person directly or indirectly; hashed identifiers are still personal
  data under GDPR-style reasoning ([ICO on pseudonymisation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-sharing/anonymisation/pseudonymisation/)).
- Notice before collection (PDPA s.23), deletion after the retention period (s.37), rules for minors (s.20)
  ([overview](https://www.dlapiperdataprotection.com/index.html?t=law&c=TH)).
- Reputational lessons: an anti-cheat client used to mine cryptocurrency on players' PCs led to a
  settlement ([NJ AG, 2013](https://nj.gov/oag/newsreleases13/pr20131119a.html)); boot-time drivers drew
  backlash ([Tom's Hardware](https://www.tomshardware.com/video-games/pc-gaming/riot-vanguard-adds-an-on-demand-mode-that-stops-anti-cheat-loading-at-boot-on-secured-windows-11-pcs)).

## DMA hardware cheats

A PCIe card reads game memory for a second PC. Device-ID checks are defeated by custom firmware; what works
today is enforcing IOMMU / Kernel DMA Protection
([docs](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-kernel-dma-protection)).
Software-only detection of well-disguised DMA devices is not credible; aeterna-rongroi can at most report
IOMMU state as posture.

## What this meant for aeterna-rongroi

- No kernel driver.
- Start with low-false-positive posture signals and robust artifacts.
- Treat noisy signals (overlays, handles, VM flags) as context for a human, never as evidence of cheating.
- Minimise data: show matches, redact user names, store nothing unless the user exports.
