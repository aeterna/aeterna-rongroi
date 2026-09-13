# Privacy

## What the tool reads

Only local artifacts needed by its collectors, for example machine security settings (Secure Boot),
FiveM's plugin folders (for GTA V Legacy and Enhanced) and the signatures of the files in them, FiveM's own program file (`FiveM.exe`) and its signature, the list of running processes, what the Program Compatibility Assistant, Windows
Prefetch and the Background Activity Moderator recorded about programs that ran, and what the Windows
event logs hold.
Each collector is listed with what it reads in [docs/architecture.md](docs/architecture.md).

Of each file in FiveM's plugin folders it reads its location, a SHA-256 of its contents, and what Windows
says about the digital signature embedded in it: whether it is valid and, when it is, the name on the
signing certificate and a hash of that certificate. **Checking a signature does not use the internet** —
the check is told to use only what Windows already holds, and the Windows CI job proves it on every
change (ADR 0035). The name on a certificate is usually a company's; some developers sign in their own
name, and that name is then what the report shows.

It reads the same four things of `FiveM.exe` in the program folder of each FiveM edition, so that the
report can say whether FiveM's own program carries the signature FiveM was measured with (ADR 0036). To
find that one file it lists the names in the program folder; **no other file there is reported**, and
nothing is read from inside it but what the hash and the signature check consume.

**Since ADR 0036 rules read these files, so SS mode shows them.** Each file in a plugin folder, and
`FiveM.exe` when its signature is not the expected one, matches a rule and is shown to the person
watching — its path with your user name replaced, its hash, its signature and the signer's name. The
consent question names them before anything is read.

Of a running process it reads the name of the program and, when Windows will say, where that program
is on disk. It does not read what a program is doing, what is in its memory, or what you typed into it.

Of a Prefetch file it reads the program's name, how many times Windows recorded it running and when it
last ran. **A Prefetch file also lists every file that program loaded — normally hundreds of paths,
some of them inside your own folders — and the disks it touched, including a serial number that
identifies your PC. None of that is reported, in either mode.** Replacing your user name inside those
paths would not help: the list itself is a description of what is on your PC, and this check has no use
for it. The report says so, rather than leaving you to notice it is missing.

Of Windows' Background Activity Moderator it reads which programs ran and when. That record is kept
**per user account**, and the account is named by a SID — an identifier of the account *and* of the
Windows installation it belongs to. **No part of that SID is reported**, hashed or otherwise: the report
says how many accounts had records and nothing else about them. The path of a program is reported only
when it starts with a drive letter, because that is the only shape SS mode knows how to redact. A path
written any other way can carry your account name with nothing to replace it, so it is withheld rather
than shown — and the report says it was withheld, rather than leaving you to notice it is missing.
Of the Windows event logs it reads **how many events of each kind each log holds** — the channel, who
wrote them, the event number, the severity and the first and last time one was written — and, of each log
itself, how far back it still reaches: the time and the record number of the oldest and the newest event
that survives in it, and how large the file was. For the folder as a whole it counts how many of the logs
it read hold no events at all and how many different channels have anything in them. None of that names a
person, and none of it is a conclusion: a log that reaches back only a few days is the ordinary result of
Windows overwriting the oldest events when the log fills, of a channel that was switched on recently, or of
a Windows upgrade, and a PC with almost every log empty is what a "PC optimiser" script leaves behind — the
report says which of these it cannot tell apart. **What each event says is not read into the report at
all**: an event's own text is where user names, PC names, addresses, account identifiers and full command
lines live, and none of it survives the step that reads the file.
A log the tool could not read — because Windows refused it, because it is larger than the tool will open,
or because the tool's own time limit ran out — is **named in the report as one it could not read**, rather
than passed over in silence. A log the tool never opened at all, because that time limit was already gone
when its turn came, is named as one it did not look at — which is a different thing and is said in
different words.

Of the machine's security settings it also reads two more (ADR 0038). One is what the PC's **firmware**
itself says about Secure Boot, beside what Windows says — one on/off value, nothing that names a person.
Windows only lets a program read a firmware value with a special permission that administrators hold, so
the tool switches that permission on inside its own process for that one read and switches it back; it
changes nothing on the PC and writes nothing to the firmware. Without administrator rights the tool does
not get the permission and says the check could not be answered. The other is whether a Windows
**policy** turns PowerShell's script logging on or off, or whether no such policy was set: the setting
only, never what any script contained.

It also reads one Windows setting about itself: whether Windows is writing a record when a program is
launched (`EnablePrefetcher`). That is a machine setting and names no person. It is read so that "there
is no record of this program" can be told apart from "Windows is not keeping such records on this PC",
which are not the same statement about you. The value, and whether the Prefetch folder is there at all,
are shown in Self mode as they were read; nothing is concluded from them.

Of each Prefetch file and each event log file it reads **one attribute: whether the file is marked
read-only**. Not when the file was made or changed, not who owns it, not its other attributes. Of each
event log whose events all belong to one channel, it asks Windows' Event Log service which file that
channel is written to and how large the service lets it grow. That is how this PC is set up, not
anything a log says, and asking changes nothing: the question is read-only. None of these names a
person, and none is a conclusion — a file can be read-only because it was restored from a backup, and a
log can be in a file Windows no longer writes because it was archived or exported.

It also reads **when Windows last started counting** — one number Windows keeps about the machine, the
time since it started — and puts it at the top of the report as a time, in both modes, so that the times
on other rows can be read against it. It names no person and says nothing about who used the PC. It is
not a conclusion and not "when you turned your PC on": a "Shut down" with Fast Startup, which is how
Windows ships, and sleep and hibernation do not start the count again, so on an ordinary PC it is often
days old. It does say roughly when the PC was last restarted, which is a small fact about your day, and
two reports taken before the next restart show the same time. The consent question names it (ADR 0039).

### When the tool says it could not answer

Every check that could not be answered says **why**, in one sentence, in your language. Several of the
reasons are the ordinary state of an ordinary PC and none of them is a finding about you:

- *"this version of Windows does not keep this record"* — the record arrived in a later Windows than
  this one.
- *"the place this is kept is there and holds nothing"* — Windows keeps such records here and there are
  none right now. Windows itself deletes some of them on a schedule, and emptying others is a common
  "speed up my PC" tip.
- *"the Windows service that writes this record is switched off"* — a setting on this PC, so nothing was
  ever written to be missing.
- *"part of this was read and part of it was not"* and *"this program stopped reading before it
  finished"* — limits of this program, not of your PC, and the report says so rather than reporting
  "nothing found".

"Not measured" means the check did not get an answer. It is not a finding.

The tool does **not** take screenshots, read browser history, access files unrelated to its collectors,
or allow remote access.

## What leaves the machine

- **aeterna-rongroi's own code sends nothing.** There is no network code; CI rejects dependencies and APIs
  that could add it.
- **The GUI uses Microsoft WebView2**, a Windows component. Microsoft documents that WebView2 collects
  some required diagnostic data regardless of settings and follows the Windows *Diagnostic data* setting
  for optional data; crash reports may be sent to Microsoft. aeterna-rongroi turns off SmartScreen inside
  its WebView and keeps the WebView profile in a temporary folder that is deleted on exit, but it cannot
  switch off Windows' own diagnostics.
- **The CLI version does not use WebView2.** Use it if you want no WebView component involved.

## What is shown

| | Self mode | SS mode (screenshare) |
|---|---|---|
| Consent screen | no | yes — you may refuse |
| Evidence shown | everything | rule matches, plus counts of what was not found or could not be answered for a reason the rule itself said is ordinary. A check this program stopped short of is shown, because that is its own limit and not a fact about your PC |
| What a collector saw that no rule matched | listed | **not listed** — only how many there were |
| Paths | full | your user-profile folder is replaced with `%USERPROFILE%` |
| When Windows last started | shown | shown, as one time at the top of the report |

### Program names are not redacted, and that can matter

SS mode replaces your user-profile folder inside **paths**: `C:\Users\<your name>\…` is shown as
`%USERPROFILE%\…`. A program's **name** is not a path and is not changed. Some installers and tools
produce an executable named after the account that installed it, so the name of a running program can
carry a real person's name to whoever is watching the screenshare.

There is no reliable way to recognise an account name inside an arbitrary name, and a guess that looks
like a guarantee would be worse than none — so aeterna-rongroi does not guess, and tells you instead.
If that matters to you, look at the report in Self mode first: you see exactly what SS mode would show,
before anyone else does.

### aeterna-rongroi's own traces

aeterna-rongroi is running while it scans, so it is in the list of running programs it reads. The report
keeps what it saw of **itself** in a separate "own traces" section instead of deleting it, and shows that
section in both modes: it is not evidence about your PC, and hiding it would tell you less about what the
tool did, not more. Paths in it are redacted in SS mode like any other.

### What a collector saw that no rule matched

Some collectors read things no rule asks about — the list of programs you are running, what Windows
recorded about programs that ran, and whether each FiveM plugin folder was there. **Self mode lists
them**, under "unmatched observations", so that you can read what the tool saw and judge it yourself.

**SS mode does not list them.** It says how many there were and nothing more. That mode promises to show
only what matches a rule, and the names of every file and every running program on your PC are not that:
they would tell whoever is watching what you have open, which is none of the check's business. Replacing
your user name in paths would not change that, so the list is withheld rather than redacted.

If you want to know what SS mode will show before anyone sees it, run Self mode first. What SS mode adds
is nothing; what it removes is this list and the evidence that did not match.

## What is stored

Nothing. The window version has no export or save button. The CLI prints the view it was asked for,
as text or with `--json` as JSON, and writes a file only if you redirect that output into one yourself;
it contains the view you asked for (SS-mode output is redacted). If you send such a file to a server's
staff, that server becomes responsible for how it keeps it. Such a file is not signed: anyone who holds
it can change it, and nothing in it shows whether they did (ADR 0040).
