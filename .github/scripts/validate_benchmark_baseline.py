"""Require a saved baseline for exactly the framework being benchmarked."""

import json
import re
import sys
from pathlib import Path


def select_suite(data, framework):
    if not re.fullmatch(r"net\d+\.\d+", framework):
        raise ValueError(f"Invalid target framework: {framework}")

    name = f"Benchmark {framework}"
    history = data.get("entries", {}).get(name)
    if not isinstance(history, list) or not history:
        raise ValueError(f"Missing framework-specific baseline: {name}")
    latest = history[-1]
    if latest.get("tool") != "benchmarkdotnet" or not latest.get("benches"):
        raise ValueError(f"Invalid or empty framework-specific baseline: {name}")
    return name


def read_data(path):
    prefix = "window.BENCHMARK_DATA = "
    text = Path(path).read_text(encoding="utf-8")
    if not text.startswith(prefix):
        raise ValueError("Expected a github-action-benchmark data.js file")
    return json.loads(text[len(prefix):].rstrip().removesuffix(";"))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("Usage: validate_benchmark_baseline.py DATA_JS FRAMEWORK")
        print(f"name={select_suite(read_data(sys.argv[1]), sys.argv[2])}")
    except (OSError, ValueError, TypeError, AttributeError) as error:
        sys.exit(f"Benchmark baseline validation failed: {error}")
