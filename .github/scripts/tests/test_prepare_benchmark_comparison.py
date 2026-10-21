import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
SCRIPT = SCRIPT_DIR / "prepare_benchmark_comparison.py"
METHOD = "Example.Benchmarks.Method(count: 10)"


def identity(iterations):
    return f"{METHOD} [job:IterationCount={iterations},LaunchCount=1,WarmupCount=3]"


def report():
    return {"HostEnvironmentInfo": {"RuntimeVersion": ".NET 10.0.13"}, "Benchmarks": [
        {"FullName": METHOD, "DisplayInfo": f"Benchmarks.Method: {job}(IterationCount={n}, LaunchCount=1, WarmupCount=3) [count=10]",
         "Statistics": {"Mean": value, "StandardDeviation": 1, "N": n},
         "Measurements": [{"Nanoseconds": value}], "Memory": {"BytesAllocatedPerOperation": 10}}
        for job, n, value in [("Job-ABCDEF", 10, 100), ("ShortRun", 3, 120)]
    ]}


def history():
    return {"entries": {"Benchmark net10.0": [{
        "commit": {"id": "older"}, "tool": "benchmarkdotnet", "benches": [
            {"name": identity(n), "value": value, "unit": "ns"}
            for n, value in [(10, 100), (3, 120)]
        ]
    }]}}


class BenchmarkComparisonTests(unittest.TestCase):
    def run_preparer(self, raw=None, saved=None, threshold=None):
        raw = report() if raw is None else raw
        saved = history() if saved is None else saved
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline, source, output = [root / x for x in ["data.js", "raw.json", "comparison.json"]]
            baseline.write_text("window.BENCHMARK_DATA = " + json.dumps(saved) + ";\n")
            source.write_text(json.dumps(raw))
            before = [p.read_bytes() for p in [baseline, source]]
            command = [sys.executable, str(SCRIPT), str(baseline), "net10.0", str(source), str(output), "current"]
            if threshold is not None:
                command.extend(["--check", threshold])
            result = subprocess.run(command,
                                    capture_output=True, text=True)
            self.assertEqual(before, [p.read_bytes() for p in [baseline, source]])
            return result, json.loads(output.read_text()) if output.exists() else None

    def test_preserves_both_jobs_and_raw_observations_with_stable_names(self):
        raw = report()
        result, prepared = self.run_preparer(raw)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = copy.deepcopy(raw)
        for b, n in zip(expected["Benchmarks"], [10, 3]):
            b["FullName"] = identity(n)
        self.assertEqual(prepared, expected)

    def test_random_job_id_does_not_change_identity(self):
        raw = report()
        raw["Benchmarks"][0]["DisplayInfo"] = raw["Benchmarks"][0]["DisplayInfo"].replace("ABCDEF", "XYZABC")
        result, prepared = self.run_preparer(raw)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(prepared["Benchmarks"][0]["FullName"], identity(10))

    def test_rejects_duplicate_current_job_identity(self):
        raw = report()
        raw["Benchmarks"].append(copy.deepcopy(raw["Benchmarks"][0]))
        result, output = self.run_preparer(raw)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate current job identity", result.stderr)
        self.assertIsNone(output)

    def test_rejects_unknown_job_configuration(self):
        raw = report()
        raw["Benchmarks"][0]["DisplayInfo"] = "Benchmarks.Method: NewJob(IterationCount=10, Runtime=Other)"
        result, output = self.run_preparer(raw)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported benchmark job configuration", result.stderr)
        self.assertIsNone(output)

    def test_rejects_missing_or_added_job_instead_of_silent_skip(self):
        for current in [report()["Benchmarks"][:1], report()["Benchmarks"] + [{
            **report()["Benchmarks"][0], "FullName": "Another.Method"}]]:
            with self.subTest(current=current):
                result, output = self.run_preparer({"Benchmarks": current})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("identity mismatch", result.stderr)
                self.assertIsNone(output)

    def test_uses_same_previous_distinct_commit_as_action(self):
        saved = history()
        same_commit = copy.deepcopy(saved["entries"]["Benchmark net10.0"][0])
        same_commit["commit"]["id"] = "current"
        same_commit["benches"] = [{"name": "SameCommitMustBeSkipped", "value": 1}]
        saved["entries"]["Benchmark net10.0"].append(same_commit)
        result, prepared = self.run_preparer(saved=saved)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(prepared)

    def test_rejects_no_previous_distinct_commit(self):
        saved = history()
        saved["entries"]["Benchmark net10.0"][0]["commit"]["id"] = "current"
        result, output = self.run_preparer(saved=saved)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No previous distinct-commit baseline", result.stderr)
        self.assertIsNone(output)

    def test_rejects_ambiguous_old_rows_without_guessing_order(self):
        saved = history()
        for b in saved["entries"]["Benchmark net10.0"][0]["benches"]:
            b["name"] = METHOD
        result, output = self.run_preparer(saved=saved)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ambiguous baseline job identity", result.stderr)
        self.assertIsNone(output)

    def test_snapshot_gate_fails_a_regression_without_refetching_history(self):
        raw = report()
        raw["Benchmarks"][0]["Statistics"]["Mean"] = 200
        result, _ = self.run_preparer(raw, threshold="105%")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Performance regression against verified snapshot", result.stderr)
        self.assertIn(identity(10), result.stderr)

    def test_threshold_boundary_is_strictly_greater_than_105_percent(self):
        raw = report()
        raw["Benchmarks"][0]["Statistics"]["Mean"] = 105
        result, _ = self.run_preparer(raw, threshold="105%")
        self.assertEqual(result.returncode, 0, result.stderr)
        raw["Benchmarks"][0]["Statistics"]["Mean"] = 105.00001
        result, _ = self.run_preparer(raw, threshold="105%")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Performance regression", result.stderr)

    def test_zero_baseline_matches_upstream_ratio_semantics(self):
        raw, saved = report(), history()
        saved["entries"]["Benchmark net10.0"][0]["benches"][0]["value"] = 0
        raw["Benchmarks"][0]["Statistics"]["Mean"] = 0
        result, _ = self.run_preparer(raw, saved, "105%")
        self.assertEqual(result.returncode, 0, result.stderr)
        raw["Benchmarks"][0]["Statistics"]["Mean"] = 1
        result, _ = self.run_preparer(raw, saved, "105%")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Performance regression", result.stderr)

    def test_invalid_current_or_previous_numbers_fail_closed(self):
        for value in [float("nan"), float("inf"), -1, True, None, "100"]:
            for target in ["current", "baseline"]:
                with self.subTest(value=value, target=target):
                    raw, saved = report(), history()
                    if target == "current":
                        raw["Benchmarks"][0]["Statistics"]["Mean"] = value
                    else:
                        saved["entries"]["Benchmark net10.0"][0]["benches"][0]["value"] = value
                    result, _ = self.run_preparer(raw, saved, "105%")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("finite nonnegative number", result.stderr)

    def test_unknown_baseline_unit_fails_closed(self):
        saved = history()
        saved["entries"]["Benchmark net10.0"][0]["benches"][0]["unit"] = "us"
        result, _ = self.run_preparer(saved=saved, threshold="105%")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported baseline unit", result.stderr)

    def test_workflow_enforces_snapshot_gate_after_store_even_if_store_fails(self):
        workflow = (SCRIPT_DIR.parent / "workflows/perform-benchmarks.yml").read_text()
        self.assertIn("id: comparison", workflow)
        self.assertIn("if: always() && steps.comparison.outcome == 'success'", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("BENCHMARK_ALERT_THRESHOLD: '105%'", workflow)
        self.assertIn("alert-threshold: ${{ env.BENCHMARK_ALERT_THRESHOLD }}", workflow)
        self.assertIn('--check "$BENCHMARK_ALERT_THRESHOLD"', workflow)


if __name__ == "__main__":
    unittest.main()
