"""Give each configured BDN job a stable comparison identity without editing raw evidence."""

import copy
import json
import math
import re
import sys
from pathlib import Path

from validate_benchmark_baseline import read_data, select_suite


def numeric_value(value, identity):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"Benchmark value must be a finite nonnegative number: {identity}")
    return value


def job_identity(benchmark):
    """Use configured iterations, never Statistics.N after outlier removal."""
    name = benchmark.get("FullName")
    if not isinstance(name, str) or not name:
        raise ValueError("Missing current benchmark FullName")
    display = benchmark.get("DisplayInfo", "")
    # Fail closed if a characteristic is added rather than silently dropping it.
    match = re.fullmatch(
        r".+: (Job-[A-Z]+|ShortRun)\(IterationCount=(10|3), "
        r"LaunchCount=1, WarmupCount=3\)(?: \[.+\])?", display
    )
    if match is None or ((match[1] == "ShortRun") != (match[2] == "3")):
        raise ValueError(f"Unsupported benchmark job configuration: {display}")
    identity = f"{name} [job:IterationCount={match[2]},LaunchCount=1,WarmupCount=3]"
    return identity, int(match[2])


def prepare_report(data, framework, report, current_commit):
    suite = select_suite(data, framework, current_commit)
    previous = next(entry for entry in reversed(data["entries"][suite])
                    if entry.get("commit", {}).get("id") != current_commit)
    expected = {benchmark["name"] for benchmark in previous["benches"]}
    for benchmark in previous["benches"]:
        if benchmark.get("unit") != "ns":
            raise ValueError(f"Unsupported baseline unit for {benchmark['name']}: {benchmark.get('unit')}")
        numeric_value(benchmark.get("value"), benchmark["name"])
    prepared = copy.deepcopy(report)
    benchmarks = prepared.get("Benchmarks")
    if not isinstance(benchmarks, list) or not benchmarks:
        raise ValueError("Missing or empty current benchmark report")
    seen = set()
    for benchmark in benchmarks:
        identity, _ = job_identity(benchmark)
        statistics = benchmark.get("Statistics")
        numeric_value(statistics.get("Mean") if isinstance(statistics, dict) else None, identity)
        if identity in seen:
            raise ValueError(f"Duplicate current job identity: {identity}")
        seen.add(identity)
        benchmark["FullName"] = identity
    if seen != expected:
        raise ValueError(
            "Benchmark job identity mismatch; missing current identities: "
            f"{sorted(expected - seen)}; identities without a verified baseline: "
            f"{sorted(seen - expected)}. No unmatched measurement may be skipped."
        )
    return prepared


def check_snapshot(data, framework, prepared, current_commit, threshold):
    if not isinstance(threshold, str) or not re.fullmatch(r"\d+(?:\.\d+)?%", threshold):
        raise ValueError("Invalid percentage threshold")
    limit = float(threshold[:-1]) / 100
    if not math.isfinite(limit) or limit <= 0:
        raise ValueError("Invalid percentage threshold")
    suite = select_suite(data, framework, current_commit)
    previous = next(entry for entry in reversed(data["entries"][suite])
                    if entry.get("commit", {}).get("id") != current_commit)
    by_name = {benchmark["name"]: benchmark for benchmark in previous["benches"]}
    failures = []
    for benchmark in prepared["Benchmarks"]:
        name = benchmark["FullName"]
        old = by_name[name]["value"]
        current = benchmark["Statistics"]["Mean"]
        ratio = current / old if old else (1 if current == 0 else math.inf)
        if ratio > limit:
            failures.append(f"{name}: {current} ns / {old} ns = {ratio:.9g} > {limit:.9g}")
    if failures:
        raise ValueError("Performance regression against verified snapshot:\n" + "\n".join(failures))
    print(f"Verified {len(prepared['Benchmarks'])} job identities against retained {suite} snapshot at {threshold}")


if __name__ == "__main__":
    try:
        if len(sys.argv) not in (6, 8) or (len(sys.argv) == 8 and sys.argv[6] != "--check"):
            raise ValueError("Usage: prepare_benchmark_comparison.py DATA_JS FRAMEWORK RAW_JSON OUTPUT_JSON CURRENT_COMMIT [--check THRESHOLD]")
        baseline_path, framework, raw_path, output_path, commit = sys.argv[1:6]
        if Path(output_path).resolve() in {Path(baseline_path).resolve(), Path(raw_path).resolve()}:
            raise ValueError("Comparison output must not overwrite baseline or raw evidence")
        data = read_data(baseline_path)
        prepared = prepare_report(data, framework,
                                  json.loads(Path(raw_path).read_text()), commit)
        Path(output_path).write_text(json.dumps(prepared, indent=2) + "\n")
        if len(sys.argv) == 8:
            check_snapshot(data, framework, prepared, commit, sys.argv[7])
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as error:
        sys.exit(f"Benchmark comparison preparation failed: {error}")
