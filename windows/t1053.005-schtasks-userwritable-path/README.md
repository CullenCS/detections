# Scheduled Task Created via Schtasks Executing From User-Writable Path

**ATT&CK:** T1053.005 — Scheduled Task (Persistence / Privilege Escalation / Execution)
**Platform / log source:** Windows process_creation (Sysmon EID 1, or Security 4688 with command-line auditing)
**Status:** validated

## The technique (why attackers do this)
After gaining initial access, attackers create scheduled tasks to survive reboots
and re-establish their foothold on a host. `schtasks.exe /create` is the built-in,
living-off-the-land way to do this, so it blends into normal Windows activity. The
tell is *where the task runs from*: malware drops its payload somewhere the current
user can write — `%AppData%`, `%Temp%`, or `C:\Users\Public` — because it rarely
has rights to write to `Program Files` or `System32`. Commodity loaders and
post-exploitation frameworks (and many real-world intrusions documented against
T1053.005) lean on exactly this pattern.

## Detection logic
The rule fires on a `process_creation` event where:
1. the image is `schtasks.exe`, and the command line contains `/create` (a task is
   being registered, not just queried or run), **and**
2. the command line references a user-writable path — `\AppData\`, `\Temp\`,
   `\Users\Public\`, or the `%APPDATA%` / `%TEMP%` environment variables.

Both conditions must be true (`selection_img and selection_path`). This deliberately
ignores task *queries* and *executions* (no `/create`) and tasks whose action runs
from a system path — those are overwhelmingly legitimate. It catches the common case
where the scheduled action's binary/script lives in a writable user directory, which
is the persistence signal.

## Validation

**Sample:** `AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx`
(from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES))

**Command run:**
```
chainsaw hunt rundll32_cmd_schtask.evtx \
  --sigma windows/t1053.005-schtasks-userwritable-path/rule.yml \
  --mapping chainsaw/mappings/sigma-event-logs-all.yml --json
```

**Result:** `1 Detections found on 1 documents`

**Matched event (Sysmon EID 1, key fields):**
```json
{
  "UtcTime":       "2020-10-23 21:57:36.627",
  "Image":         "C:\\Windows\\SysWOW64\\schtasks.exe",
  "CommandLine":   "schtasks  /Create /f /XML C:\\Users\\IEUser\\AppData\\Local\\Temp\\sduchxll.tmp /TN DataUsageHandlers",
  "ParentImage":   "C:\\Windows\\SysWOW64\\cmd.exe",
  "ParentCommandLine": "\"C:\\Windows\\System32\\cmd.exe\"  /C schtasks /Create /f /XML C:\\Users\\IEUser\\AppData\\Local\\Temp\\sduchxll.tmp /TN DataUsageHandlers",
  "User":          "MSEDGEWIN10\\IEUser",
  "CurrentDirectory": "C:\\Users\\IEUser\\AppData\\Local\\Temp\\tmp1375\\"
}
```

The rule triggered on the `/Temp/` path in the `CommandLine` field (`selection_path` matched `\Temp\`).
The parent chain (`cmd.exe` spawning `schtasks.exe`) is a classic LOLBin delivery pattern
consistent with the malware loader behavior documented in this sample.

## False positives & tuning
Legitimate software does occasionally schedule tasks from user-writable paths —
chiefly per-user auto-updaters (Chrome/Google Update, Microsoft Teams, Zoom,
Dropbox, Slack) that install under `%LocalAppData%`. Tune by:
- **ParentImage / signature:** allowlist tasks whose creating process is a *signed*
  binary from a known vendor path; alert on unsigned or LOLBin parents
  (`powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`).
- **Task name / action allowlist:** maintain a known-good list of update task names
  per managed image; anything off-list is suspicious.
- **User context:** task creation by a service/admin account during a maintenance
  window is lower-risk than creation by a standard user right after a phishing click.
Start at `level: medium`, monitor a week of your environment's baseline, then
promote to high once the vendor-updater noise is filtered.

## Gaps & evasions (honesty section)
- **Direct API / COM:** an attacker can register a task via the Task Scheduler COM
  interface or `schtasks` alternatives, never spawning `schtasks.exe` — this rule
  won't see that. Complement with a Sysmon EID 1 watch on the Task Scheduler
  service and registry/EID-4698 ("a scheduled task was created") telemetry.
- **Living in a non-monitored path:** payload staged in a writable directory not in
  the path list (e.g., a custom folder under the user profile) evades the string
  match. Broaden cautiously, or pair with a signed-parent check instead of pure
  path matching.
- **XML import:** `schtasks /create /xml` points at a task definition file; the
  user-writable path may live in the XML, not the command line. Add a selection for
  `/xml` + writable path, and consider parsing EID 4698's task XML.
