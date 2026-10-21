"""Validate the action's immutable local commit before any remote publication."""

import contextlib
import json
import math
import subprocess
import sys
from pathlib import Path

from prepare_benchmark_comparison import check_snapshot, numeric_value, prepare_report
from validate_benchmark_baseline import read_data, select_suite


DATA_PATH = "dev/bench/data.js"
INDEX_PATH = "dev/bench/index.html"


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def git_data(commit):
    text = git("show", f"{commit}:{DATA_PATH}")
    prefix = "window.BENCHMARK_DATA = "
    if not text.startswith(prefix):
        raise ValueError("Expected a github-action-benchmark data.js file")
    return json.loads(text[len(prefix):].rstrip().removesuffix(";"))


def same_json(left, right):
    """Exact JSON equality through the action's JS Number roundtrip, not epsilon."""
    if type(left) in (int, float) and type(right) in (int, float):
        try:
            return math.isfinite(float(left)) and math.isfinite(float(right)) and float(left) == float(right)
        except OverflowError:
            return False
    if type(left) is not type(right):
        return False  # In particular, JSON true is not the number 1.
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_json(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    return left == right


def validate_publication(retained, framework, raw, current_commit, threshold):
    candidate = git("rev-parse", "refs/heads/gh-pages^{commit}").strip()
    parents = git("rev-list", "--parents", "-n", "1", candidate).split()
    if len(parents) != 2:
        raise ValueError("Prepared commit must have exactly one parent")
    parent = parents[1]
    changed = set(git("diff-tree", "--no-commit-id", "--name-only", "-r", candidate).splitlines())
    if DATA_PATH not in changed or not changed <= {DATA_PATH, INDEX_PATH}:
        raise ValueError("Unexpected prepared commit files")
    if INDEX_PATH in changed:
        existing = subprocess.run(["git", "cat-file", "-e", f"{parent}:{INDEX_PATH}"], capture_output=True)
        if existing.returncode == 0:
            raise ValueError("Prepared commit must not replace an existing index")

    # The action refetches/pulls. Its prepared commit's parent, not FETCH_HEAD or
    # origin/gh-pages, is the exact history it used. Require both snapshots.
    base = git_data(parent)
    for snapshot in (retained, base):
        prepared = prepare_report(snapshot, framework, raw, current_commit)
        check_snapshot(snapshot, framework, prepared, current_commit, threshold)
    suite = select_suite(base, framework, current_commit)
    updated = git_data(candidate)
    entries = updated.get("entries", {})
    previous = base["entries"]
    current_history = entries.get(suite)
    if (set(entries) != set(previous) or not isinstance(current_history, list)
            or len(current_history) != len(previous[suite]) + 1
            or not same_json(current_history[:-1], previous[suite])
            or any(not same_json(entries[name], value) for name, value in previous.items() if name != suite)):
        raise ValueError("Prepared commit must preserve history and append exactly one result")
    entry = current_history[-1]
    if entry.get("commit", {}).get("id") != current_commit or entry.get("tool") != "benchmarkdotnet":
        raise ValueError("Prepared result has the wrong commit or tool")
    expected = {row["FullName"]: row["Statistics"]["Mean"] for row in prepared["Benchmarks"]}
    benches = entry.get("benches")
    if not isinstance(benches, list) or len(benches) != len(expected):
        raise ValueError("Prepared result differs from raw measurements")
    seen = set()
    for bench in benches:
        name = bench.get("name")
        value = numeric_value(bench.get("value"), name)
        if name in seen or name not in expected or bench.get("unit") != "ns" or not same_json(value, expected[name]):
            raise ValueError("Prepared result differs from raw measurements")
        seen.add(name)
    return candidate


if __name__ == "__main__":
    try:
        if len(sys.argv) != 6:
            raise ValueError("Usage: validate_benchmark_publication.py SNAPSHOT FRAMEWORK RAW_JSON CURRENT_COMMIT THRESHOLD")
        snapshot, framework, source, commit, threshold = sys.argv[1:]
        # Keep stdout suitable for GITHUB_OUTPUT; validation diagnostics go to stderr.
        with contextlib.redirect_stdout(sys.stderr):
            candidate = validate_publication(read_data(snapshot), framework,
                                             json.loads(Path(source).read_text()), commit, threshold)
        print(f"commit={candidate}")
    except (OSError, ValueError, TypeError, AttributeError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(f"Benchmark publication validation failed: {error}")
