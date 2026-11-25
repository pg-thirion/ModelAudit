"""Command-line interface."""
import argparse
import re
from pathlib import Path
import sys

from .adapters import DemoTarget, HttpTarget
from .engine import evaluate, exit_code
from .suite import load_suite
from .reporting import write_report, compare_baseline, write_text
from .advanced import select_cases, plan, export_report
from . import __version__


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Authorised LLM security regression tests")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--plan", action="store_true", help="Validate and preview without contacting a target")
    target.add_argument("--demo", choices=["secure", "vulnerable"])
    target.add_argument("--endpoint", help="Authorised staging endpoint URL")
    parser.add_argument("--adapter", choices=["generic", "chat"], default="generic")
    parser.add_argument("--model")
    parser.add_argument("--suite", type=Path, default=Path(__file__).with_name("default_suite.json"))
    parser.add_argument("--repeat", type=int, choices=range(1, 11), default=1)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--output", type=Path, help="Write a JSON report")
    parser.add_argument("--confirm-fixtures", action="store_true", help="Attest authorised staging, seeded canaries and sandboxed tools")
    parser.add_argument("--target-label", help="Non-sensitive stable application/environment identifier")
    parser.add_argument("--baseline", type=Path, help="Compare a compatible previous report")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--category", action="append", default=[])
    parser.add_argument("--severity", action="append", default=[])
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--seed", type=int)
    parser.add_argument("--max-requests", type=int, default=2000)
    parser.add_argument("--interval", type=float, default=0)
    parser.add_argument("--deadline", type=float)
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--junit", type=Path)
    parser.add_argument("--html", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.endpoint and (not args.confirm_fixtures or not args.target_label):
            raise ValueError("Live evaluation requires fixture attestation and target label")
        if args.target_label and not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", args.target_label):
            raise ValueError("Invalid target label")
        outputs = [p.resolve() for p in (args.output, args.csv, args.junit, args.html) if p]
        protected = [p.resolve() for p in (args.suite, args.baseline) if p]
        if len(outputs) != len(set(outputs)) or set(outputs) & set(protected):
            raise ValueError("Outputs must be unique and not overwrite inputs")
        cases = select_cases(load_suite(args.suite), args.category, args.severity, args.case, args.seed)
        preview = plan(cases, args.repeat, args.max_requests)
        if not 0 <= args.interval <= 60 or (args.deadline is not None and not 0 < args.deadline <= 86400):
            raise ValueError("Invalid execution limits")
        if args.plan:
            print(preview)
            return 0
        if args.endpoint and not any(c.category == "positive_control" and (c.required or c.required_events) for c in cases):
            raise ValueError("Live suites require a positive control")
        if args.endpoint and args.adapter == "chat" and any(c.required_events or c.forbidden_events for c in cases):
            raise ValueError("Chat adapter does not support trusted event evidence")
        adapter = (DemoTarget(args.demo == "vulnerable") if args.demo else
                   HttpTarget(args.endpoint, args.adapter, args.model, args.timeout))
        report = evaluate(cases, adapter, args.repeat, max_requests=args.max_requests, interval=args.interval, deadline=args.deadline)
        report["model"] = args.model
        report["execution_policy"] = {"interval": args.interval, "deadline": args.deadline, "seed": args.seed, "timeout": args.timeout}
        report["target_type"] = "simulation" if args.demo else args.adapter
        report["target_label"] = args.target_label
        report["fixture_attestation"] = bool(args.endpoint and args.confirm_fixtures)
        if args.demo:
            report["simulation_profile"] = args.demo
        if args.baseline:
            report["comparison"] = compare_baseline(args.baseline, report)
        if args.output:
            write_report(args.output, report)
        for format_name in ("csv", "junit", "html"):
            path = getattr(args, format_name)
            if path:
                write_text(path, export_report(report, format_name))
        print(f"ModelAudit: {report['counts']} | Gate: {report['release_gate'].upper()}")
        for result in report["results"]:
            print(f"  {result['status'].upper():5} {result['severity']:8} {result['id']}")
        return exit_code(report)
    except (ValueError, OSError, TypeError, RecursionError):
        print("ModelAudit: invalid configuration, suite or report path", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
