# New AWS IAM Access Key Created For an Existing User

**ATT&CK:** T1098.001 — Account Manipulation: Additional Cloud Credentials (Persistence)
**Platform / log source:** AWS CloudTrail (`AWSCloudTrail` table in Microsoft Sentinel / Log Analytics)

**Status:** draft

## The technique (why attackers do this)
Long-lived IAM access keys are durable credentials. An attacker who has gained
some access calls `iam:CreateAccessKey` to mint a new key — often on a *different*,
more privileged user — so they keep a foothold even if the original entry point
is closed. It is quiet: a single successful API call that looks like routine
administration.

## Detection logic
Queries `AWSCloudTrail` for successful `CreateAccessKey` events and compares the
**actor** (`UserIdentityUserName`) to the **target** (`RequestParameters.userName`).
When they differ — someone creating a key *for another user* — it surfaces the
event with source IP, region, user agent, and whether the session was MFA-backed.
Service-linked automation (`UserIdentityType == AWSService`) is excluded.

## Validation
<!-- Owner step: load an OTRF Security-Datasets AWS CloudTrail dataset containing
CreateAccessKey activity into an Azure Data Explorer free cluster, run this KQL,
and paste the real result row(s) here, then set Status: validated. Reproduce
steps in /VALIDATION.md. If no dataset covers CreateAccessKey-for-another-user,
state that and validate the field logic against a sample CreateAccessKey event. -->

_Pending validation in Azure Data Explorer against OTRF Security-Datasets AWS CloudTrail telemetry (see [/VALIDATION.md](../../VALIDATION.md))._

## False positives & tuning
Admins and IAM automation legitimately create keys. Tune by allowlisting known
provisioning principals (your IaC/CI roles), and treat **actor != target** plus
**MFA not used** plus a **new source IP/ASN** as the high-confidence combination.
Self-service key rotation (actor == target) is intentionally excluded to cut noise.

## Gaps & evasions (honesty section)
- Persistence via other credential types — `CreateLoginProfile`, attaching a new
  policy, or an STS role chain — won't show as CreateAccessKey. Pair with
  detections for those API calls.
- An attacker operating *as* the target user (actor == target after compromising
  that identity) evades the actor!=target heuristic; complement with
  impossible-travel / new-ASN detection on the console/API session.
