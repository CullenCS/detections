# detections

Production-style detection rules, each validated in a lab against the real
technique and documented like I'd hand it to a SOC: detection logic, log
sources, false-positive tuning, and known gaps. Mapped to MITRE ATT&CK.

| Rule | Technique | Platform | Status |
|------|-----------|----------|--------|
| [Scheduled task from user-writable path](windows/t1053.005-schtasks-userwritable-path/) | T1053.005 | Windows | draft |

(table grows as rules land — see BACKLOG.md)

**Why these writeups exist:** a rule without tuning notes and validation
evidence isn't a detection, it's a regex. Each entry shows the full lifecycle:
threat research → logic → lab validation → FP analysis → coverage honesty.

Lab: <!-- TODO(Cullen): one line describing your lab before pushing public, e.g.
"Windows Server 2022 + Sysmon (SwiftOnSecurity config) shipped to Microsoft
Sentinel; attacker box running Atomic Red Team." -->
