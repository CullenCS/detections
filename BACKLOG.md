# Detection backlog

Shipped so far (7 rules; see [README](README.md)): five Windows (Sigma) and two
cloud (KQL). The newest, PowerShell script-block logging (EID 4104), is authored
and passing CI but its Chainsaw validation run is still pending.

Candidate next rules:
- T1078 Valid Accounts: anomalous sign-in from a new ASN/country (Entra)
- T1110.003 Password spraying across many accounts (Entra SigninLogs)

Each follows TEMPLATE/README.md.
