# LSASS Process Memory Access With Credential-Dumping Access Mask

**ATT&CK:** T1003.001 OS Credential Dumping: LSASS Memory (Credential Access)
**Platform / log source:** Windows process_access (Sysmon EID 10)
**Status:** validated

## The technique (why attackers do this)
LSASS holds the secrets of logged-on users: NTLM hashes, Kerberos tickets, and
sometimes cleartext credentials. After landing on a host, attackers read LSASS
memory to harvest those credentials and move laterally. Tools like Mimikatz
(`sekurlsa::logonpasswords`) and the `comsvcs.dll MiniDump` LOLBin open a handle
to lsass with read/query rights, so the access *mask* on that handle is the tell.

## Detection logic
Fires on a Sysmon EID 10 (ProcessAccess) where `TargetImage` is `lsass.exe` and
`GrantedAccess` is one of the masks associated with reading process memory
(`0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`). These are the
credential-dumping masks tracked by the canonical Sigma LSASS-access rule, and
every one ORs in `PROCESS_VM_READ` (`0x10`): `0x1010` is the minimal Mimikatz
`sekurlsa` read, the `0x14xx` family adds `PROCESS_QUERY_INFORMATION` plus
VM-operation/write rights used by several dumpers, and `0x1fffff` is
`PROCESS_ALL_ACCESS` (procdump and friends). A short allowlist removes
the most common benign readers (Defender's `MsMpEng.exe`, `wmiprvse.exe`,
`taskmgr.exe`). The mask-based approach catches handle opens regardless of the
tool name, which is why it survives renamed binaries.

## Validation

Validated against two real attack EVTX samples from the EVTX-ATTACK-SAMPLES corpus.
No masks were fabricated. Every value below comes straight from the captured events.

### Sample 1: Mimikatz sekurlsa::logonpasswords

**Command:**
```
chainsaw hunt sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx \
  --sigma rule.yml \
  --mapping sigma-event-logs-all.yml \
  --json
```

**Result:** 1 detection on 1 document

**Matched event (EID 10):**
```json
{
  "UtcTime": "2019-03-17 19:37:11.641",
  "SourceImage": "C:\\Users\\IEUser\\Desktop\\mimikatz_trunk\\Win32\\mimikatz.exe",
  "TargetImage": "C:\\Windows\\system32\\lsass.exe",
  "GrantedAccess": "0x1010",
  "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+4595c|C:\\Windows\\system32\\KERNELBASE.dll+8185|C:\\Users\\IEUser\\Desktop\\mimikatz_trunk\\Win32\\mimikatz.exe+5c5a9|...",
  "SourceProcessId": 3588,
  "TargetProcessId": 476
}
```

`GrantedAccess 0x1010` = `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, the
canonical Mimikatz sekurlsa handle mask.

### Sample 2: Procdump LSASS memory dump

**Command:**
```
chainsaw hunt sysmon_10_11_lsass_memdump.evtx \
  --sigma rule.yml \
  --mapping sigma-event-logs-all.yml \
  --json
```

**Result:** 1 detection on 1 document

**Matched event (EID 10):**
```json
{
  "UtcTime": "2019-03-17 19:09:41.328",
  "SourceImage": "C:\\Users\\IEUser\\Desktop\\procdump.exe",
  "TargetImage": "C:\\Windows\\system32\\lsass.exe",
  "GrantedAccess": "0x1fffff",
  "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+4595c|...|C:\\Windows\\system32\\dbghelp.dll+4c791|...|C:\\Users\\IEUser\\Desktop\\procdump.exe+11a8d|...",
  "SourceProcessId": 1856,
  "TargetProcessId": 476
}
```

`GrantedAccess 0x1fffff` = `PROCESS_ALL_ACCESS`, used by procdump and similar dump
utilities that request maximum rights. The `CallTrace` confirms `dbghelp.dll`
involvement, the canonical MiniDump stack fingerprint.

## False positives & tuning
Legitimate readers of LSASS exist: AV/EDR, some backup and monitoring agents,
and Windows itself. Tune by **SourceImage**: build the allowlist from a week of
your own EID 10 baseline, alert on unsigned or LOLBin source processes
(`rundll32.exe`, `powershell.exe`), and watch `CallTrace` for `dbgcore.dll` /
`dbghelp.dll` (MiniDump). Keep the mask list tight. Broadening to all access
masks reintroduces noise.

## Gaps & evasions (honesty section)
- Attackers can dump LSASS without opening a classic handle: via a driver,
  PPL bypass, or `MiniDumpWriteDump` from a process already allowlisted. Pair
  with EID 10 CallTrace analysis and detections for LSASS dump *files*.
- Access-mask evasion: some tooling requests lower masks (`0x1000`) and elevates
  later. Monitor for handle-rights upgrades rather than only the final mask.
