# MFA Fatigue / Push-Bombing in Entra ID Sign-Ins

**ATT&CK:** T1621 — Multi-Factor Authentication Request Generation (Credential Access)
**Platform / log source:** Microsoft Entra ID sign-in logs (`SigninLogs` in Sentinel)

**Status:** draft

## The technique (why attackers do this)
When an attacker already has a valid password (from phishing or a dump), the only
thing left is MFA. Push-bombing spams the user with approval prompts — at 2am, or
dozens in a row — betting the user eventually taps "approve" to make it stop. It
is how several high-profile 2022–2023 intrusions got past MFA.

## Detection logic
Counts failed strong-auth events (`ResultType 500121`) per user in a rolling
10-minute window; `>= 5` denials is the fatigue signal. It then left-joins to any
successful sign-in for that user shortly after the burst and flags
`LikelyApproved = true` — the dangerous case where the user finally accepted.
Threshold and window are tunable knobs at the top of the query.

## Validation
<!-- Owner step: load an OTRF Security-Datasets Azure/Entra sign-in dataset (or a
representative SigninLogs export) into an Azure Data Explorer free cluster, run
this KQL, and paste the real result here, then set Status: validated. If no public
dataset reproduces a push-bombing burst, say so explicitly and validate the field
logic (ResultType 500121, AuthenticationDetails) against a single real SigninLogs
event's schema. Do not fabricate a burst. -->

_Pending validation in Azure Data Explorer against OTRF Security-Datasets Entra sign-in telemetry (see [/VALIDATION.md](../../VALIDATION.md))._

## False positives & tuning
Real users fail MFA — fat-fingered prompts, flaky connectivity, a new phone.
Tune the **threshold/window** to your population, and raise confidence when the
burst pairs with a **new IP/country**, an **unfamiliar client app**, or a
**`LikelyApproved` success from a different IP** than the denials. A single user
on a bad network is benign; ten users denied-then-approved in an hour is an incident.

## Gaps & evasions (honesty section)
- A patient attacker can send prompts slowly (one every few hours) to stay under
  the window/threshold. Add a longer-horizon, lower-rate variant.
- Number-matching MFA and FIDO2 defeat push-bombing outright — this detection is
  for tenants still on plain push approval; note that in deployment.
- Token theft / AiTM phishing bypasses MFA without prompts at all; complement
  with anomalous-token and impossible-travel detections.
