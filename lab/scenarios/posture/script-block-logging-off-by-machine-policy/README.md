# Script block logging off by machine policy

## What the trace stands for

A machine policy that turns Windows PowerShell 5.1 script block logging off: `EnableScriptBlockLogging` is `0`
under `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`. PowerShell code that runs on
this machine leaves no 4104 record in the event log.

## What the scenario shows

The posture collector reads the machine policy, and `posture/logging/script-block-logging-disabled-by-policy`
reads `found`. The three neighbours stay `not_found`: the per-user policy rule (the machine key exists, so the
account's key is not read), PowerShell 7's policy rule (its own key is absent), and PowerShell 7's per-user rule.

## What the scenario does not show

- Who set the policy, or why. A PC managed by an organisation may set it; that alone says nothing about the
  person using the PC.
- PowerShell 7's configuration file. The collector does not read it, and this scenario does not test it.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md) and
[ADR 0038](../../../../docs/adr/0038-firmware-secure-boot-and-script-block-logging-policy.md).
