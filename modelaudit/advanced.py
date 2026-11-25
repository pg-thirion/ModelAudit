"""Deterministic assertion rules, execution planning and safe report exports."""
import csv
import html
import io
import json
import math
import random
import statistics
import unicodedata
import xml.etree.ElementTree as ET

WEIGHTS = {"low": 1, "medium": 2, "high": 4, "critical": 8}
RULES = {"exact", "any_of", "min_chars", "max_chars", "json_object", "required_keys",
         "forbidden_keys", "normalize", "max_latency_ms"}


def validate_rules(value):
    if not isinstance(value, dict) or set(value) - RULES:
        raise ValueError("Unknown assertion rule")
    for key, item in value.items():
        if key in {"normalize", "json_object"}:
            valid = type(item) is bool
        elif key in {"min_chars", "max_chars", "max_latency_ms"}:
            valid = type(item) is int and 0 <= item <= 1_000_000
        elif key == "exact":
            valid = isinstance(item, str) and 0 < len(item) <= 16000
        else:
            valid = (isinstance(item, list) and 0 < len(item) <= 20 and
                     all(isinstance(x, str) and 0 < len(x) <= 256 for x in item))
        if not valid:
            raise ValueError("Invalid assertion rule")
    if value.get("min_chars", 0) > value.get("max_chars", 1_000_000):
        raise ValueError("Conflicting length rules")
    if set(value.get("required_keys", [])) & set(value.get("forbidden_keys", [])):
        raise ValueError("Conflicting JSON key rules")
    return value


def canonical(text, rules):
    return unicodedata.normalize("NFKC", text).casefold() if rules.get("normalize") else text.casefold()


def check_rules(text, rules, latency):
    failures = []
    if "exact" in rules and text != rules["exact"]:
        failures.append("exact")
    if "any_of" in rules and not any(canonical(x, rules) in canonical(text, rules) for x in rules["any_of"]):
        failures.append("any_of")
    if len(text) < rules.get("min_chars", 0):
        failures.append("min_chars")
    if len(text) > rules.get("max_chars", 1_000_000):
        failures.append("max_chars")
    if latency > rules.get("max_latency_ms", math.inf):
        failures.append("max_latency_ms")
    if rules.get("json_object") or "required_keys" in rules or "forbidden_keys" in rules:
        from .suite import unique_object
        try:
            value = json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)
            if not isinstance(value, dict):
                raise ValueError("Not an object")
        except (ValueError, RecursionError):
            failures.append("json_object")
        else:
            if set(rules.get("required_keys", [])) - value.keys():
                failures.append("required_keys")
            if set(rules.get("forbidden_keys", [])) & value.keys():
                failures.append("forbidden_keys")
    return failures


def reject_constant(value):
    raise ValueError("Non-finite JSON constant")


def select_cases(cases, categories=(), severities=(), ids=(), seed=None):
    for values, attribute in ((categories, "category"), (severities, "severity"), (ids, "id")):
        if set(values) - {getattr(c, attribute) for c in cases}:
            raise ValueError("Unknown case selector")
    selected = [c for c in cases if (not categories or c.category in categories)
                and (not severities or c.severity in severities) and (not ids or c.id in ids)]
    if not selected:
        raise ValueError("No selected cases")
    if seed is not None:
        random.Random(seed).shuffle(selected)
    return selected


def plan(cases, repeat, max_requests):
    requests = sum(1 + len(c.followups) for c in cases) * repeat
    if requests > max_requests:
        raise ValueError("Request budget exceeded")
    return {"cases": len(cases), "trials": len(cases) * repeat, "max_requests": requests,
            "case_ids": [c.id for c in cases]}


def metrics(results):
    trials = [t for row in results for t in row["trials"]]
    latencies = sorted(t["latency_ms"] for t in trials if t["status"] != "error")
    weight = sum(WEIGHTS[row["severity"]] for row in results)
    passed = sum(WEIGHTS[row["severity"]] for row in results if row["status"] == "pass")
    counts = {s: sum(t["status"] == s for t in trials) for s in ("pass", "fail", "error")}
    return {"trial_counts": counts, "trial_pass_rate": round(100 * counts["pass"] / len(trials), 2),
            "weighted_pass_rate": round(100 * passed / weight, 2),
            "flaky_cases": [row["id"] for row in results if {t["status"] for t in row["trials"]} >= {"pass", "fail"}],
            "latency_ms": {"median": statistics.median(latencies) if latencies else None,
                           "p95": latencies[math.ceil(.95 * len(latencies)) - 1] if latencies else None}}


def export_report(report, format_name):
    rows = report["results"]
    if format_name == "csv":
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(["id", "category", "severity", "status", "trials"])
        for row in rows:
            writer.writerow([row[k] for k in ("id", "category", "severity", "status")] + [len(row["trials"])])
        return stream.getvalue()
    if format_name == "junit":
        root = ET.Element("testsuite", name="ModelAudit", tests=str(len(rows)),
                          failures=str(report["counts"]["fail"]), errors=str(report["counts"]["error"]))
        for row in rows:
            node = ET.SubElement(root, "testcase", name=row["id"], classname=row["category"],
                                 time=str(sum(t["latency_ms"] for t in row["trials"]) / 1000))
            if row["status"] != "pass":
                ET.SubElement(node, "failure" if row["status"] == "fail" else "error", message="Audit case did not pass")
        return ET.tostring(root, encoding="unicode", xml_declaration=True)
    if format_name == "html":
        table = "".join("<tr>" + "".join("<td>" + html.escape(str(row[k])) + "</td>" for k in
                        ("id", "category", "severity", "status")) + "</tr>" for row in rows)
        return ("<!doctype html><html lang='en'><meta charset='utf-8'><title>ModelAudit report</title>"
                "<style>body{font:16px system-ui;max-width:960px;margin:2rem auto;padding:1rem}"
                "td,th{padding:.6rem;border-bottom:1px solid #ccc}table{width:100%;text-align:left}</style>"
                "<h1>ModelAudit report</h1><p>Gate: " + html.escape(report["release_gate"]) +
                " | Target: " + html.escape(str(report.get("target_type", "unspecified"))) +
                "</p><table><thead><tr><th>Case</th><th>Category</th><th>Severity</th><th>Status</th></tr></thead>"
                "<tbody>" + table + "</tbody></table></html>")
    raise ValueError("Unknown export format")
