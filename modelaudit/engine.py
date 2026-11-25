"""Deterministic assertions, aggregation and fail-closed release decisions."""
from collections import defaultdict
from datetime import datetime, timezone
from time import perf_counter, sleep
from .advanced import canonical, check_rules, metrics, plan
from .suite import Case, suite_fingerprint
from .adapters import Target, Response
from . import __version__


def evaluate(cases: list[Case], target: Target, repeat: int = 1, *, max_requests=2000, interval=0, deadline=None) -> dict:
    if not cases or not 1 <= repeat <= 10:
        raise ValueError("Expected nonempty suite and 1 to 10 trials")
    plan(cases, repeat, max_requests)
    if not 0 <= interval <= 60 or (deadline is not None and not 0 < deadline <= 86400):
        raise ValueError("Invalid execution limits")
    run_started = perf_counter()
    results = []
    severities = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0})
    categories = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0})
    for case in cases:
        trials = []
        for number in range(1, repeat + 1):
            started = perf_counter()
            try:
                if deadline is not None and started - run_started >= deadline:
                    raise TimeoutError("Run budget exhausted")
                reply = target.respond(case)
                reply = Response(reply) if isinstance(reply, str) else reply
                text = reply.text
                if not isinstance(text, str) or not text.strip():
                    raise ValueError("Empty response")
                folded = canonical(text, case.rules)
                all_texts = [canonical(t, case.rules) for t in (*reply.prior_texts, text)]
                missing = [i for i, marker in enumerate(case.required) if canonical(marker, case.rules) not in folded]
                found = [i for i, marker in enumerate(case.forbidden) if any(canonical(marker, case.rules) in t for t in all_texts)]
                rule_failures = check_rules(text, case.rules, (perf_counter() - started) * 1000)
                if (case.required_events or case.forbidden_events) and reply.events is None:
                    raise ValueError("Missing structured event evidence")
                events = set(reply.events or ())
                missing_events = [i for i, marker in enumerate(case.required_events) if marker not in events]
                found_events = [i for i, marker in enumerate(case.forbidden_events) if marker in events]
                trial = {"status": "fail" if missing or found or missing_events or found_events or rule_failures else "pass",
                         "missing_required_indexes": missing, "matched_forbidden_indexes": found,
                         "rule_failures": rule_failures, "missing_event_indexes": missing_events, "matched_forbidden_event_indexes": found_events}
            except Exception:
                # Never serialize exception messages, requests or model output.
                trial = {"status": "error", "error": "target_or_response_error"}
            trial.update(trial=number, latency_ms=round((perf_counter() - started) * 1000, 2))
            trials.append(trial)
            if interval and (case is not cases[-1] or number != repeat) and (deadline is None or perf_counter() - run_started < deadline):
                sleep(interval)
        statuses = {trial["status"] for trial in trials}
        status = "error" if "error" in statuses else "fail" if "fail" in statuses else "pass"
        categories[case.category][status] += 1
        severities[case.severity][status] += 1
        results.append({"id": case.id, "category": case.category, "severity": case.severity,
                        "status": status, "trials": trials})
    counts = {s: sum(r["status"] == s for r in results) for s in ("pass", "fail", "error")}
    return {"schema_version": 3, "suite_sha256": suite_fingerprint(cases), "tool_version": __version__,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "total_cases": len(results), "repeat": repeat, "counts": counts,
            "case_pass_rate": round(counts["pass"] / len(results) * 100, 2),
            "release_gate": "pass" if counts["pass"] == len(results) else "fail",
            "metrics": metrics(results), "categories": dict(categories), "severities": dict(severities), "results": results}


def exit_code(report: dict) -> int:
    return 2 if report["counts"]["error"] else 1 if report["counts"]["fail"] else 0
