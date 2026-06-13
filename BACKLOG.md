# Detection backlog (ship one every 1–2 weeks)

2. T1003.001 — LSASS memory access (Sysmon EID 10, GrantedAccess masks) — Windows
3. T1059.001 — PowerShell encoded/obfuscated command execution — Windows
4. T1098.001 — New AWS IAM access key created for existing user (CloudTrail) — cloud,
   plays directly to the cloud background
5. T1621 — MFA fatigue / push-bombing pattern in Entra ID sign-in logs — cloud/identity
6. T1543.003 — Windows service creation from non-standard path — Windows

Each follows TEMPLATE/README.md. Cloud detections (4, 5) differentiate the
portfolio — most public repos are Windows-only, and they showcase the user's
cloud+SOC crossover.
