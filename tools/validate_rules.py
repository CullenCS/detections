#!/usr/bin/env python3
"""Validate the detection rules in this repo.

Run on every push by CI (.github/workflows/ci.yml) so a malformed detection
cannot land on main. Checks two things:

  Windows Sigma rules (windows/*/rule.yml):
    - parses as YAML
    - has the required Sigma keys (title, id, status, logsource, detection)
    - id is a real UUID
    - detection defines a condition and at least one selection
    - status is a valid Sigma value
    - ships with a README.md writeup beside it

  Cloud KQL rules (cloud/*/detection.kql):
    - is non-empty
    - ships with a README.md writeup beside it

Exit code is 0 when everything passes, 1 otherwise.
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
REQUIRED_SIGMA_KEYS = ("title", "id", "status", "logsource", "detection")
VALID_SIGMA_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}

errors: list[str] = []
checked = 0


def fail(path: Path, message: str) -> None:
    errors.append(f"{path.relative_to(REPO)}: {message}")


def check_sigma(rule_path: Path) -> None:
    global checked
    checked += 1
    try:
        doc = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        fail(rule_path, f"invalid YAML ({exc.__class__.__name__})")
        return
    if not isinstance(doc, dict):
        fail(rule_path, "rule is not a YAML mapping")
        return

    for key in REQUIRED_SIGMA_KEYS:
        if key not in doc:
            fail(rule_path, f"missing required key '{key}'")

    rule_id = doc.get("id")
    if rule_id is not None:
        try:
            uuid.UUID(str(rule_id))
        except ValueError:
            fail(rule_path, f"id '{rule_id}' is not a valid UUID")

    detection = doc.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            fail(rule_path, "detection has no 'condition'")
        if len(detection) < 2:
            fail(rule_path, "detection has a condition but no selections")
    elif "detection" in doc:
        fail(rule_path, "detection must be a mapping")

    status = doc.get("status")
    if status is not None and status not in VALID_SIGMA_STATUS:
        fail(rule_path, f"status '{status}' is not a valid Sigma status")

    if not (rule_path.parent / "README.md").is_file():
        fail(rule_path, "no README.md writeup beside the rule")


def check_kql(kql_path: Path) -> None:
    global checked
    checked += 1
    if not kql_path.read_text(encoding="utf-8").strip():
        fail(kql_path, "detection.kql is empty")
    if not (kql_path.parent / "README.md").is_file():
        fail(kql_path, "no README.md writeup beside the detection")


def main() -> int:
    for rule in sorted((REPO / "windows").glob("*/rule.yml")):
        check_sigma(rule)
    for kql in sorted((REPO / "cloud").glob("*/detection.kql")):
        check_kql(kql)

    if checked == 0:
        print("no rules found to validate", file=sys.stderr)
        return 1
    if errors:
        print(f"FAIL: {len(errors)} problem(s) across {checked} rule(s):")
        for problem in errors:
            print(f"  - {problem}")
        return 1
    print(f"OK: {checked} rule(s) validated, no problems.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
