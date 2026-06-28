Detections

[![validate-detections](https://github.com/CullenCS/detections/actions/workflows/ci.yml/badge.svg)](https://github.com/CullenCS/detections/actions/workflows/ci.yml)

Production-style detection rules mapped to MITRE ATT&CK, each documented like I'd
hand it to a SOC: detection logic, log sources, false-positive tuning, and known
gaps. Windows rules are validated against real attack telemetry
(EVTX-ATTACK-SAMPLES, run with Chainsaw); the cloud rules' validation in Azure
Data Explorer is in progress.

| Rule | Technique | Platform | Status |
|------|-----------|----------|--------|
| [Scheduled task from user-writable path](windows/t1053.005-schtasks-userwritable-path/) | T1053.005 | Windows | validated |
| [LSASS memory access (credential-dumping mask)](windows/t1003.001-lsass-memory-access/) | T1003.001 | Windows | validated |
| [PowerShell encoded command](windows/t1059.001-powershell-encoded-command/) | T1059.001 | Windows | validated |
| [PowerShell script-block logging (decoded content)](windows/t1059.001-powershell-scriptblock/) | T1059.001 | Windows | draft |
| [Service from user-writable / script path](windows/t1543.003-service-nonstandard-path/) | T1543.003 | Windows | validated |
| [AWS IAM access key for existing user](cloud/t1098.001-aws-iam-key-created/) | T1098.001 | AWS | draft |
| [Entra MFA fatigue / push-bombing](cloud/t1621-entra-mfa-fatigue/) | T1621 | Entra ID | draft |

(table grows as rules land; see BACKLOG.md)

**Why these writeups exist:** without tuning notes and validation evidence, a rule
is just a regex. Each entry walks the full lifecycle: threat research, detection
logic, validation against public attack telemetry, false-positive analysis, and an
honest account of the gaps it leaves open.

**Validation:** Windows rules are tested against [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) with [Chainsaw](https://github.com/WithSecureLabs/chainsaw); cloud rules against [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) in Azure Data Explorer. See [VALIDATION.md](VALIDATION.md).

**Continuous validation:** every push runs a CI check ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)): `yamllint` on the Sigma rule files, a Python validator ([`tools/validate_rules.py`](tools/validate_rules.py)) that enforces the structure I rely on (required Sigma keys, a valid UUID id, a real detection condition, and a writeup beside every rule), and `sigma check` from the official Sigma toolchain to validate each rule against the Sigma spec. A malformed detection fails the build instead of landing on main.
