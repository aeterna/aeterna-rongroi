# 07 — Red team methodology and detection validation

Gathered **2026-10-18** to place this project's detection-validation work (ADR 0074, ADR 0075, ADR 0076)
beside the established security discipline. It is a methodology and tooling survey, read from the primary
sources linked below; it contains no offensive procedure. A snapshot — re-check anything before relying on
it. **(vendor claim)** marks a claim a project makes about itself; **(unverified)** marks what the research
could not confirm against a primary source this session.

## Why this note exists

This project's "red" side is narrow by design (`AGENTS.md` purpose boundary): it only shows that a rule
reads a trace that is really there. It never tests whether a trace can be hidden, removed or forged — that
stays a private report through `SECURITY.md`. The industry calls this narrow, cooperative form **purple
teaming / detection validation**, and its standard loop is exactly what ADR 0076 describes. This note records
where our design sits in that discipline and the one gap it makes obvious.

## The discipline

- **MITRE ATT&CK** (<https://attack.mitre.org>) is the field's common language: a knowledge base of
  *tactics* (why), *techniques* and *sub-techniques* (how), each with a stable id such as `T1070` (indicator
  removal) or `T1053.005` (scheduled task). Red emulation, a detection rule, and a threat report all cross-walk
  through the same id.
- Other frameworks: the **Cyber Kill Chain** (Lockheed Martin) — a 7-stage narrative model, coarser than
  ATT&CK; **PTES** (<http://www.pentest-standard.org>) and **NIST SP 800-115**
  (<https://csrc.nist.gov/pubs/sp/800/115/final>) — engagement standards (prepare → discover → attack →
  report); **TIBER-EU** (ECB, 2025 edition) and **CREST** — organisation-level frameworks and certification.
- **Red vs pentest vs purple.** A *pentest* finds as many flaws as possible within a scope. A *red team*
  emulates a specific adversary to test whether detection and response work, and stealth matters. *Purple
  teaming* drops the wall: red runs a technique, blue confirms the telemetry and rule fired, the gap is fixed
  on the spot. The *assume-breach* model starts from an already-compromised host to spend the budget on
  detection, not on the first foothold. **This project is a purple-team / detection-validation use.**

## Detection validation — the loop we follow

The standard loop: run a *known* technique in an isolated lab → confirm the expected telemetry and rule
fired → record coverage → tune the rule → repeat. Open-source projects that embody it:

| Project | What it is | Licence | Source |
|---|---|---|---|
| Atomic Red Team (Red Canary) | small "atomic" tests, one per ATT&CK technique, in **YAML** (`atomics/T<id>/T<id>.yaml`) | open source | <https://github.com/redcanaryco/atomic-red-team> |
| MITRE Caldera | automated adversary-emulation platform, ATT&CK-based | open source | <https://github.com/mitre/caldera> |
| Sigma (SigmaHQ) | generic YAML format for log-based detections; `pySigma` converts to SIEM queries | open source | <https://github.com/SigmaHQ/sigma> |
| Elastic detection-rules | Elastic's public KQL/EQL rules, CI-tested, mapped to ATT&CK | open source | <https://github.com/elastic/detection-rules> |
| ATT&CK Navigator | colour the ATT&CK matrix as coverage layers | open source | <https://github.com/mitre-attack/attack-navigator> |
| DeTT&CT (Rabobank CDC) | score data-source quality, visibility and detection coverage; emit Navigator layers | open source | <https://github.com/rabobank-cdc/DeTTECT> |
| Stratus Red Team (Datadog) | cloud adversary emulation, each technique mapped to ATT&CK | open source | <https://github.com/DataDog/stratus-red-team> |
| Infection Monkey (Akamai) | breach-and-attack-simulation agent for lateral movement / segmentation | GPLv3 | <https://github.com/guardicore/monkey> |

**Lab / range** projects run techniques only in isolated, throwaway environments with a snapshot →
detonate → revert workflow: **DetectionLab** (unverified canonical repo), **Splunk Attack Range**
(<https://github.com/splunk/attack_range>), **GOAD — Game of Active Directory**
(<https://github.com/Orange-Cyberdefense/GOAD>). Windows telemetry comes from **Sysmon**, the **Windows
Event Logs**, **ETW**, and EDR sensors.

## Windows forensic artifacts — what we already read

Artifacts that activity leaves and blue teams hunt, tied to ATT&CK, and whether this project has a collector:

| Artifact | ATT&CK (example) | Our collector |
|---|---|---|
| Prefetch, Amcache, ShimCache, BAM/DAM, SRUM | execution / `T1059` | `prefetch` ✅, `bam` ✅; Amcache parked (ADR 0041) |
| Run keys, scheduled tasks, services | `T1547.001`, `T1053.005`, `T1543.003` | `autostart` ✅ |
| `$MFT`, USN journal | indicator removal `T1070` | `usn` ✅ |
| Security / System / PowerShell / Sysmon logs | `T1021`, `T1003` | `evtx` ✅, `powershell_text` ✅ |

The standard DFIR parsers for these are Eric Zimmerman's tools, KAPE, Velociraptor, Autopsy and Volatility.
This project writes its own parsers because it must be offline, read-only and report evidence, never a
verdict (ADR 0002, ADR 0003).

## Where our design sits

| Industry practice | This project |
|---|---|
| Atomic test: one technique in YAML | `scenario` in ADR 0076 (`setup.ps1` + `expect.yaml`) |
| snapshot → detonate → revert | throwaway overlay of the lab disk (ADR 0076 §1) |
| detection = rule in YAML | `rule.yaml`, format v4 |
| coverage layer over a matrix | the coverage table (ADR 0074) |
| indicator-removal (`T1070`) is itself a trace | the log-clearing rules |
| run only on owned / authorised, isolated systems | the ADR 0069 virtual machine; never a player's PC |

## The gap this makes obvious

**Our rules carry no ATT&CK technique id.** Adding one to each rule would give the project the field's common
language: coverage comparable against the standard matrix (which techniques we read traces for, which we do
not), and a cross-walk to Atomic Red Team and Sigma. This is a documentation/metadata change, needs no lab,
and is the natural next ADR. It is noted here, not decided.

What stays out of scope, whatever the framework: anything that hides, removes or forges a trace, or presents a
machine as clean. A way past a rule, if found, is a private `SECURITY.md` report, not a repository artifact.
