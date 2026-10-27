# PowerShell 7 script block logging off by machine policy

## What the trace stands for

A machine policy that turns PowerShell 7 script block logging off: `EnableScriptBlockLogging` is a `REG_DWORD`
`0` under `HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging`. PowerShell 7 code that runs on
this machine leaves no 4104 record in the event log. PowerShell 7 need not be installed for the trace to be
on the machine: the policy is a registry value either way.

## What the scenario shows

The posture collector reads the machine policy, and `posture/logging/pwsh-script-block-logging-disabled-by-policy`
reads `found`. The three neighbours stay `not_found`: the Windows PowerShell policy rule and its per-user rule
(Windows PowerShell's machine key is absent, so neither reads a policy), and PowerShell 7's per-user rule (the
machine key exists, so the account's key is not read).

## What the scenario does not show

- Who set the policy, or why. A PC managed by an organisation may set it; that alone says nothing about the
  person using the PC.
- PowerShell 7's configuration file. The collector does not read it, and this scenario does not test it.
- Whether PowerShell 7 is installed on the machine, or how it behaves with the policy in place. The scenario
  shows only what the collector reads from the registry.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md) and
[ADR 0038](../../../../docs/adr/0038-firmware-secure-boot-and-script-block-logging-policy.md).
