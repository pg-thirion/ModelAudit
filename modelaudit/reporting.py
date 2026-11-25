"""Private atomic reports and strict comparable-baseline checks."""
import json
import os
from pathlib import Path
import tempfile

from .suite import unique_object


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".modelaudit-", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(report, handle, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def compare_baseline(path: Path, report: dict) -> dict:
    if path.stat().st_size > 10_000_000:
        raise ValueError("Baseline exceeds 10 MB")
    baseline = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(baseline, dict):
        raise ValueError("Invalid baseline")
    for key in ("schema_version", "suite_sha256", "repeat", "target_type",
                "target_label", "simulation_profile"):
        if baseline.get(key) != report.get(key):
            raise ValueError("Incompatible baseline")
    def statuses(value):
        rows = value["results"]
        if not isinstance(rows, list):
            raise ValueError("Invalid results")
        result = {}
        for row in rows:
            if not isinstance(row, dict) or row.get("status") not in {"pass", "fail", "error"}:
                raise ValueError("Invalid result status")
            key = row["id"]
            if not isinstance(key, str) or key in result:
                raise ValueError("Invalid result ID")
            result[key] = row["status"]
        return result
    try:
        old, new = statuses(baseline), statuses(report)
    except (KeyError, TypeError) as exc:
        raise ValueError("Invalid baseline results") from exc
    if old.keys() != new.keys():
        raise ValueError("Baseline has different case IDs")
    return {
        "regressions": sorted(key for key in new if old[key] == "pass" and new[key] != "pass"),
        "recoveries": sorted(key for key in new if old[key] != "pass" and new[key] == "pass"),
    }
