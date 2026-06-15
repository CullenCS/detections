# PowerShell Script Block Logging Reveals Download/Exec or In-Memory Loading

**ATT&CK:** T1059.001 Command and Scripting Interpreter: PowerShell (Execution)
**Platform / log source:** Windows PowerShell Operational log, EID 4104 (Script Block Logging)
**Status:** draft (validation pending, see below)

## The technique (why attackers do this)
Attackers obfuscate PowerShell so the payload never appears as readable text at the
command line: base64 via `-EncodedCommand`, string concatenation, compression. The
counter is Script Block Logging (EID 4104), which records the script *after*
PowerShell deobfuscates it, just before execution. So the decoded payload, the part
the attacker tried to hide, lands in the log. This rule reads that decoded content
for the behaviors a malicious script almost always needs: pull a stage from the
network, decode it, and run or inject it.

## Detection logic
Fires on EID 4104 where the `ScriptBlockText` contains an indicator from any of
three groups:
1. **Download / fetch:** `IEX`, `Invoke-Expression`, `Net.WebClient`,
   `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Start-BitsTransfer`.
2. **Decode / load:** `FromBase64String`, `Reflection.Assembly`, `Add-Type`.
3. **Inject:** `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`.

Any one group is enough to surface for triage (`condition: ... or ... or ...`). The
high-confidence case is a single script that does all three: download, decode, then
inject. This rule is the complement to the
[encoded-command rule](../t1059.001-powershell-encoded-command/), which catches the
`-enc` flag at process creation; this one catches the decoded payload in 4104, so
together they cover the obfuscated command line and the revealed content.

## Validation
_Pending a Chainsaw run against EVTX-ATTACK-SAMPLES (the corpus lives outside this
repo, gitignored)._ Reproduce:
```
chainsaw hunt "EVTX-ATTACK-SAMPLES/Execution" \
  --sigma windows/t1059.001-powershell-scriptblock/rule.yml \
  --mapping mappings/sigma-event-logs-all.yml --json
```
The corpus has `Microsoft-Windows-PowerShell%4Operational` samples with decoded
4104 content (IEX download cradles, reflective loaders). Once the matched event is
captured, paste it here and bump `status` to `test`, the same way the other Windows
rules were validated.

## False positives & tuning
Legitimate automation uses these cmdlets: installers call `Add-Type`, deployment
scripts call `Invoke-WebRequest`, dev tooling uses `IEX`. The single-group match is
a triage signal, not a high-severity alert on its own. Tune by:
- **Require multiple groups:** download plus decode plus inject in one script block
  is rarely benign; promote that combination, keep single-group matches at lower
  severity.
- **Baseline by host/user:** a build server pulling packages looks different from a
  workstation running an IEX download cradle minutes after a phishing click.
- **Parent/initiator context:** correlate with the EID 4104 host and the process
  that started PowerShell.

## Gaps & evasions (honesty section)
- **Script Block Logging must be enabled.** If the tenant doesn't turn it on (GPO /
  registry), there's no 4104 to read. Pair with process_creation detections that do
  not depend on it.
- **String-level evasion:** an attacker can break indicators across variables
  (`'Down' + 'loadString'`) so the literal substring never appears. Script block
  logging still records the assembled call in many cases, but not always; consider
  4104 plus AMSI telemetry for the hardest cases.
- **Volume:** 4104 is noisy on PowerShell-heavy estates. This rule is a content
  filter on top of that stream, not a standalone high-fidelity alert.
