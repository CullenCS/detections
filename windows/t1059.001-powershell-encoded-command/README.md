# PowerShell Encoded Command Execution

**ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell (Execution)
**Platform / log source:** Windows process_creation (Sysmon EID 1, or Security 4688 with command-line auditing)
**Status:** validated

## The technique (why attackers do this)
`-EncodedCommand` takes a base64 blob of a UTF-16LE script, so the actual code
never appears as readable text on the command line. Loaders, macro payloads, and
C2 stagers lean on it to defeat naive string inspection and to pass multi-line
scripts as a single argument. Legitimate interactive administration almost never
needs it, which is what makes it a useful signal.

## Detection logic
Fires when `powershell.exe`/`pwsh.exe` is launched and the command line contains
an `-EncodedCommand` form (`-enc`, `-ec`, and spacing/colon variants). PowerShell
accepts truncated parameter names, so the rule covers the common short forms.
This deliberately does not try to decode the blob inline — the presence of the
flag plus context (parent, user) is the trigger; decoding is a triage step.

## Validation

Validated against real attack telemetry using Chainsaw v2 and the EVTX-ATTACK-SAMPLES
corpus. The rule produced **1 detection on 1 document** across 345 EVTX files.

**Sample:** `EVTX-ATTACK-SAMPLES/Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx`
(IIS webshell post-exploitation; PowerShell spawned from `w3wp.exe` to XOR-decrypt and
execute a dropped module, then enumerate IIS application pools.)

**Matched EID 1 event (Sysmon process_creation):**

```json
{
  "UtcTime": "2019-05-27 01:28:42.700",
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"  -nop -noni -enc JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAiAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAIgA7...",
  "ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
  "User": "IIS APPPOOL\\DefaultAppPool",
  "IntegrityLevel": "High"
}
```

**Chainsaw command used:**
```
chainsaw hunt <corpus> \
  --sigma windows/t1059.001-powershell-encoded-command/rule.yml \
  --mapping mappings/sigma-event-logs-all.yml
```

Result: `[+] 1 Detections found on 1 documents`

The matching pattern was `' -enc '` — the malware passed its payload as
`powershell.exe -nop -noni -enc <base64blob>`, which the rule catches via the
space-delimited short form.

## False positives & tuning
The real FP source is automation: SCCM, some vendor installers, and CI/CD agents
that run encoded commands. Tune by **ParentImage** (allowlist signed
`ccmexec.exe`, your build agents), and raise severity when the parent is a LOLBin
or an Office app (`winword.exe`, `excel.exe`, `mshta.exe`, `wscript.exe`). Decode
and review the blob for `IEX`, `DownloadString`, `FromBase64String` on the survivors.

## Gaps & evasions (honesty section)
- Encoding is only one obfuscation path: attackers can run plain `-Command`,
  read from a file, or use `IEX (New-Object Net.WebClient)...` with no `-enc`.
  Complement with Script Block Logging (EID 4104) detections.
- `-enc` can be split or cased oddly; command-line contains-matching is robust to
  case but not to characters injected between letters. Pair with 4104 for the
  decoded content.
