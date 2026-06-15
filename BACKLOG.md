# Detection backlog

The initial set has shipped (6 rules — see [README](README.md)): four Windows
(Sigma) and two cloud (KQL).

Candidate next rules:
- T1078 — Valid Accounts: anomalous sign-in from a new ASN/country (Entra)
- T1110.003 — Password spraying across many accounts (Entra SigninLogs)
- EID 4104 — PowerShell script-block logging: decoded malicious content

Each follows TEMPLATE/README.md.
