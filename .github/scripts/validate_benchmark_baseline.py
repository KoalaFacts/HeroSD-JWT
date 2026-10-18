"""Require a saved baseline for exactly the framework being benchmarked."""

import json
import re
import sys
from pathlib import Path


def select_suite(data, framework, current_commit=None):
    if not re.fullmatch(r"net\d+\.\d+", framework):
        raise ValueError(f"Invalid target framework: {framework}")

    name = f"Benchmark {framework}"
    history = data.get("entries", {}).get(name)
    if not isinstance(history, list) or not history:
        raise ValueError(f"Missing framework-specific baseline: {name}")
    latest = history[-1]
    if current_commit is not None:
        latest = next((entry for entry in reversed(history)
                       if entry.get("commit", {}).get("id") != current_commit), None)
        if latest is None:
            raise ValueError(f"No previous distinct-commit baseline: {name}")
    if latest.get("tool") != "benchmarkdotnet" or not latest.get("benches"):
        raise ValueError(f"Invalid or empty framework-specific baseline: {name}")
    seen = set()
    for benchmark in latest["benches"]:
        identity = benchmark.get("name") if isinstance(benchmark, dict) else None
        if not isinstance(identity, str) or not identity:
            raise ValueError(f"Invalid benchmark identity in baseline: {name}")
        if identity in seen:
            raise ValueError(
                f"Ambiguous baseline job identity in {name}: {identity}. "
                "Historical rows do not identify their jobs; recover verified job "
                "provenance before comparison. Do not infer jobs from row order, "
                "discard rows, or reset the baseline."
            )
        seen.add(identity)
    return name


def read_data(path):
    prefix = "window.BENCHMARK_DATA = "
    text = Path(path).read_text(encoding="utf-8")
    if not text.startswith(prefix):
        raise ValueError("Expected a github-action-benchmark data.js file")
    return json.loads(text[len(prefix):].rstrip().removesuffix(";"))


if __name__ == "__main__":
    try:
        if len(sys.argv) not in (3, 4):
            raise ValueError("Usage: validate_benchmark_baseline.py DATA_JS FRAMEWORK [CURRENT_COMMIT]")
        commit = sys.argv[3] if len(sys.argv) == 4 else None
        print(f"name={select_suite(read_data(sys.argv[1]), sys.argv[2], commit)}")
    except (OSError, ValueError, TypeError, AttributeError) as error:
        sys.exit(f"Benchmark baseline validation failed: {error}")
