"""Strict schema validation for local JSON test suites."""
from dataclasses import dataclass, field as dataclass_field
import json
import hashlib
from dataclasses import asdict
from pathlib import Path
import re
from .advanced import validate_rules

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
    forbidden_events: tuple[str, ...] = ()
    required_events: tuple[str, ...] = ()
    followups: tuple[str, ...] = ()
    rules: dict = dataclass_field(default_factory=dict)


def load_suite(path: Path) -> list[Case]:
    if path.stat().st_size > 1_000_000:
        raise ValueError("Suite exceeds 1 MB")
    payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(payload, list) or not 1 <= len(payload) <= 200:
        raise ValueError("Suite must contain 1 to 200 cases")
    cases = []
    seen = set()
    for item in payload:
        if not isinstance(item, dict) or set(item) - {"id", "category", "severity", "prompt", "required", "forbidden", "rationale", "forbidden_events", "required_events", "followups", "rules"}:
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
        forbidden_events, required_events = markers("forbidden_events"), markers("required_events")
        if any(not re.fullmatch(r"[a-z0-9_-]+", v) for v in forbidden_events + required_events):
            raise ValueError("Invalid event identifier")
        followups = item.get("followups", [])
        if not isinstance(followups, list) or len(followups) > 5 or any(not isinstance(v, str) or not v.strip() or len(v) > 16000 for v in followups):
            raise ValueError("Invalid followup prompts")
        rules = validate_rules(item.get("rules", {}))
        rationale = item.get("rationale", "")
        if severity not in SEVERITIES or case_id in seen or not (required or forbidden or forbidden_events or required_events or any(k != "normalize" and (k != "json_object" or v) for k, v in rules.items())):
            raise ValueError("Invalid severity, duplicate ID or missing assertions")
        if set(required) & set(forbidden) or set(required_events) & set(forbidden_events):
            raise ValueError("Conflicting assertions")
        if not isinstance(rationale, str) or len(rationale) > 1000:
            raise ValueError("Invalid rationale")
        seen.add(case_id)
        cases.append(Case(case_id, category, severity, field("prompt", 16000),
                          required, forbidden, rationale, forbidden_events, required_events, tuple(followups), rules))
    return cases

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def suite_fingerprint(cases: list[Case]) -> str:
    canonical = json.dumps([asdict(case) for case in cases], sort_keys=True,
                           ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()
