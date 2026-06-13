# {{RULE_TITLE}}

**ATT&CK:** {{TECHNIQUE_ID}} — {{TECHNIQUE_NAME}} ({{TACTIC}})
**Platform / log source:** {{e.g., Windows process_creation (Sysmon EID 1)}}
**Status:** draft | validated

## The technique (why attackers do this)
{{3–5 sentences: what the attacker gains, when in the kill chain it appears,
one real-world campaign reference if known.}}

## Detection logic
{{Explain the rule.yml in prose: what fields, why these conditions, what
variations it catches and deliberately ignores.}}

## Validation
{{How it was tested: the exact command/Atomic Red Team test run in the lab,
and the resulting event/alert (screenshot or pasted event excerpt).}}

## False positives & tuning
{{What legitimately triggers this (installers, admin tools), and the specific
exclusions/filters to handle them. THIS SECTION IS WHAT PROVES SENIORITY.}}

## Gaps & evasions (honesty section)
{{How an attacker evades this rule, and what complementary detection covers it.}}
