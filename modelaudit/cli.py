"""Command-line interface."""
import argparse
import re
from pathlib import Path
import sys

from .adapters import DemoTarget, HttpTarget
from .engine import evaluate, exit_code
from .suite import load_suite
from .reporting import write_report, compare_baseline


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Authorised LLM security regression tests")
    target = parser.add_mutually_exclusive_group(required=True)
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
    args = parser.parse_args(argv)
    try:
        if args.endpoint and (not args.confirm_fixtures or not args.target_label):
            raise ValueError("Live evaluation requires fixture attestation and target label")
        if args.target_label and not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", args.target_label):
            raise ValueError("Invalid target label")
        if args.output and (args.output.resolve() == args.suite.resolve() or
                            (args.baseline and args.output.resolve() == args.baseline.resolve())):
            raise ValueError("Output must not overwrite suite or baseline")
        cases = load_suite(args.suite)
        if args.endpoint and not any(c.category == "positive_control" and (c.required or c.required_events) for c in cases):
            raise ValueError("Live suites require a positive control")
        adapter = (DemoTarget(args.demo == "vulnerable") if args.demo else
                   HttpTarget(args.endpoint, args.adapter, args.model, args.timeout))
        report = evaluate(cases, adapter, args.repeat)
        report["target_type"] = "simulation" if args.demo else args.adapter
        report["target_label"] = args.target_label
        report["fixture_attestation"] = bool(args.endpoint and args.confirm_fixtures)
        if args.demo:
            report["simulation_profile"] = args.demo
        if args.baseline:
            report["comparison"] = compare_baseline(args.baseline, report)
        if args.output:
            write_report(args.output, report)
        print(f"ModelAudit: {report['counts']} | Gate: {report['release_gate'].upper()}")
        for result in report["results"]:
            print(f"  {result['status'].upper():5} {result['severity']:8} {result['id']}")
        return exit_code(report)
    except (ValueError, OSError, TypeError, RecursionError):
        print("ModelAudit: invalid configuration, suite or report path", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
