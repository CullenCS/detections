# Windows Service Installed From a User-Writable or Script Path

**ATT&CK:** T1543.003 Create or Modify System Process: Windows Service (Persistence / Privilege Escalation)
**Platform / log source:** Windows System log, EID 7045 (a service was installed)

**Status:** validated

## The technique (why attackers do this)
A Windows service runs automatically and as SYSTEM, so installing one is a clean
way to get both persistence and privilege escalation in a single move. Malware
and post-exploitation frameworks (PsExec-style lateral movement, Cobalt Strike's
service jobs) register a service whose binary lives wherever the attacker could
write (typically a user-writable directory), or whose ImagePath is a script
interpreter carrying the payload inline.

## Detection logic
Fires on System EID 7045 (service installed) when the `ImagePath` either points
into a user-writable directory (`\AppData\`, `\Temp\`, `\Users\Public\`,
`\ProgramData\`) or invokes a script interpreter (`powershell`, `cmd.exe`,
`%COMSPEC%`, `cscript`, `wscript`, `rundll32`). Service binaries overwhelmingly
live in `Program Files` or `System32`; a service pointing at a writable path or
a LOLBin is the anomaly.

**Field-name note:** Chainsaw exposes the service binary as `ImagePath` directly
inside `EventData`, confirmed against real telemetry before finalising the rule.
The original draft searched for `cmd.exe /c` (with the ` /c` suffix); real corpus
events showed the ImagePath as bare `cmd.exe` and as `%COMSPEC% /c ...`, so both
patterns were added to `path_script`.

## Validation

Validated against two attack-sample EVTX files using Chainsaw with the project
mapping. **3 detections fired, 0 false negatives.**

```
chainsaw hunt \
  "EVTX-ATTACK-SAMPLES/Lateral Movement/LM_Remote_Service02_7045.evtx" \
  "EVTX-ATTACK-SAMPLES/Privilege Escalation/System_7045_namedpipe_privesc.evtx" \
  --sigma windows/t1543.003-service-nonstandard-path/rule.yml \
  --mapping chainsaw/mappings/sigma-event-logs-all.yml \
  --json
```

**Match 1:** lateral-movement PsExec-style service, `spoolfool` masquerading as
spooler, ImagePath `cmd.exe`:
```json
{
  "timestamp": "2019-03-03T09:20:28Z",
  "ServiceName": "spoolfool",
  "ImagePath": "cmd.exe",
  "AccountName": "LocalSystem",
  "Computer": "WIN-77LTAPHIQ1R.example.corp"
}
```

**Match 2:** same session, service renamed `spoolsv` to further blend in,
ImagePath `cmd.exe`:
```json
{
  "timestamp": "2019-03-03T09:24:24Z",
  "ServiceName": "spoolsv",
  "ImagePath": "cmd.exe",
  "AccountName": "LocalSystem",
  "Computer": "WIN-77LTAPHIQ1R.example.corp"
}
```

**Match 3:** named-pipe impersonation privesc (WinPwnage), ImagePath is an
inline `%COMSPEC% /c` command writing to a named pipe:
```json
{
  "timestamp": "2019-05-12T12:52:43Z",
  "ServiceName": "WinPwnage",
  "ImagePath": "%COMSPEC% /c ping -n 1 127.0.0.1 >nul && echo 'WinPwnage' > \\\\.\\pipe\\WinPwnagePipe",
  "AccountName": "LocalSystem",
  "Computer": "IEWIN7"
}
```

## False positives & tuning
`\ProgramData\` is the noisy one; some legitimate vendors install services there.
Tune by allowlisting known-good **service names** and **signed** ImagePaths, and
keep the script-interpreter selection (a service that *is* powershell/cmd is
almost never legitimate). Start at high; if ProgramData noise is heavy in your
estate, split it into its own lower-severity variant.

## Gaps & evasions (honesty section)
- An attacker can install the binary to `System32`/`Program Files` first (needs
  admin) and then register the service from there. This path-based rule won't
  fire on that. Pair with service-creation-by-suspicious-parent and binary-signature
  checks.
- Services can be created via the registry directly (no 7045). Complement with
  Sysmon registry detections on `HKLM\SYSTEM\CurrentControlSet\Services`.
