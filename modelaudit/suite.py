"""Strict schema validation for local JSON test suites."""
from dataclasses import dataclass
import json
from pathlib import Path
import re

SEVERITIES = {"low", "medium", "high", "critical"}

@dataclass(frozen=True)
class Case:
    id: str
    category: str
    severity: str
    prompt: str
    required: tuple[str, ...]
    forbidden: tuple[str, ...]
    rationale: str = ""


def load_suite(path: Path) -> list[Case]:
    if path.stat().st_size > 1_000_000:
        raise ValueError("Suite exceeds 1 MB")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not 1 <= len(payload) <= 200:
        raise ValueError("Suite must contain 1 to 200 cases")
    cases = []
    seen = set()
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("Each case must be an object")
        def field(name, maximum):
            value = item.get(name)
            if not isinstance(value, str) or not value.strip() or len(value) > maximum:
                raise ValueError(f"Invalid field: {name}")
            return value
        def markers(name):
            values = item.get(name, [])
            if not isinstance(values, list) or len(values) > 20:
                raise ValueError(f"Invalid marker list: {name}")
            if any(not isinstance(v, str) or not v.strip() or len(v) > 256 for v in values):
                raise ValueError(f"Invalid marker: {name}")
            return tuple(v.casefold() for v in values)
        case_id = field("id", 64)
        category = field("category", 64)
        if not all(re.fullmatch(r"[a-zA-Z0-9_-]+", v) for v in (case_id, category)):
            raise ValueError("IDs and categories must be alphanumeric identifiers")
        severity = field("severity", 16)
        required, forbidden = markers("required"), markers("forbidden")
        rationale = item.get("rationale", "")
        if severity not in SEVERITIES or case_id in seen or not (required or forbidden):
            raise ValueError("Invalid severity, duplicate ID or missing assertions")
        if set(required) & set(forbidden):
            raise ValueError("Conflicting assertions")
        if not isinstance(rationale, str) or len(rationale) > 1000:
            raise ValueError("Invalid rationale")
        seen.add(case_id)
        cases.append(Case(case_id, category, severity, field("prompt", 16000),
                          required, forbidden, rationale))
    return cases
