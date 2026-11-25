"""Deterministic assertions, aggregation and fail-closed release decisions."""
from collections import defaultdict
from datetime import datetime, timezone
from time import perf_counter
from .suite import Case
from .adapters import Target
from . import __version__


def evaluate(cases: list[Case], target: Target, repeat: int = 1) -> dict:
    if not cases or not 1 <= repeat <= 10:
        raise ValueError("Expected nonempty suite and 1 to 10 trials")
    results = []
    categories = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0})
    for case in cases:
        trials = []
        for number in range(1, repeat + 1):
            started = perf_counter()
            try:
                text = target.respond(case)
                if not isinstance(text, str) or not text.strip():
                    raise ValueError("Empty response")
                folded = text.casefold()
                missing = [i for i, marker in enumerate(case.required) if marker not in folded]
                found = [i for i, marker in enumerate(case.forbidden) if marker in folded]
                trial = {"status": "fail" if missing or found else "pass",
                         "missing_required_indexes": missing, "matched_forbidden_indexes": found}
            except Exception:
                # Never serialize exception messages, requests or model output.
                trial = {"status": "error", "error": "target_or_response_error"}
            trial.update(trial=number, latency_ms=round((perf_counter() - started) * 1000, 2))
            trials.append(trial)
        statuses = {trial["status"] for trial in trials}
        status = "error" if "error" in statuses else "fail" if "fail" in statuses else "pass"
        categories[case.category][status] += 1
        results.append({"id": case.id, "category": case.category, "severity": case.severity,
                        "status": status, "trials": trials})
    counts = {s: sum(r["status"] == s for r in results) for s in ("pass", "fail", "error")}
    return {"schema_version": 1, "tool_version": __version__,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "total_cases": len(results), "repeat": repeat, "counts": counts,
            "case_pass_rate": round(counts["pass"] / len(results) * 100, 2),
            "release_gate": "pass" if counts["pass"] == len(results) else "fail",
            "categories": dict(categories), "results": results}


def exit_code(report: dict) -> int:
    return 2 if report["counts"]["error"] else 1 if report["counts"]["fail"] else 0
