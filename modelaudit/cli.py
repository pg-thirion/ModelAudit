"""Command-line interface."""
import argparse
import json
from pathlib import Path
import sys

from .adapters import DemoTarget, HttpTarget
from .engine import evaluate, exit_code
from .suite import load_suite


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
    args = parser.parse_args(argv)
    try:
        cases = load_suite(args.suite)
        adapter = (DemoTarget(args.demo == "vulnerable") if args.demo else
                   HttpTarget(args.endpoint, args.adapter, args.model, args.timeout))
        report = evaluate(cases, adapter, args.repeat)
        report["target_type"] = "simulation" if args.demo else args.adapter
        if args.demo:
            report["simulation_profile"] = args.demo
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"ModelAudit: {report['counts']} | Gate: {report['release_gate'].upper()}")
        for result in report["results"]:
            print(f"  {result['status'].upper():5} {result['severity']:8} {result['id']}")
        return exit_code(report)
    except (ValueError, OSError, TypeError):
        print("ModelAudit: invalid configuration, suite or report path", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
