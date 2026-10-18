import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "baseline", SCRIPT_DIR / "validate_benchmark_baseline.py"
)
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


class BenchmarkBaselineTests(unittest.TestCase):
    def test_rejects_ambiguous_duplicate_job_names_without_changing_history(self):
        import copy
        data = {"entries": {"Benchmark net10.0": [{
            "tool": "benchmarkdotnet", "benches": [
                {"name": "IssueWithHmac(50)", "value": 206014.1846923828},
                {"name": "IssueWithHmac(50)", "value": 239807.73502604166},
            ],
        }]}}
        original = copy.deepcopy(data)
        with self.assertRaisesRegex(ValueError, "Ambiguous.*job.*IssueWithHmac"):
            baseline.select_suite(data, "net10.0")
        self.assertEqual(data, original)

    def test_rejects_duplicate_names_even_when_values_match(self):
        data = {"entries": {"Benchmark net8.0": [{
            "tool": "benchmarkdotnet", "benches": [
                {"name": "SameMethod", "value": 1},
                {"name": "SameMethod", "value": 1},
            ],
        }]}}
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            baseline.select_suite(data, "net8.0")

    def test_selects_only_the_requested_framework(self):
        data = {"entries": {
            f"Benchmark net{version}.0": [{
                "tool": "benchmarkdotnet",
                "benches": [{"name": "SameMethod", "value": version}],
            }]
            for version in (8, 9, 10)
        }}
        for version in (8, 9, 10):
            name = baseline.select_suite(data, f"net{version}.0")
            self.assertEqual(name, f"Benchmark net{version}.0")
            self.assertEqual(data["entries"][name][-1]["benches"][0]["value"], version)

    def test_does_not_fall_back_to_another_framework_or_legacy_history(self):
        history = [{"tool": "benchmarkdotnet", "benches": [{"value": 1}]}]
        for name in ("Benchmark", "Benchmark net9.0", "Benchmark net10.0"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "Missing.*net8.0"):
                    baseline.select_suite({"entries": {name: history}}, "net8.0")

    def test_missing_or_empty_history_fails(self):
        for history in (None, [], [{"tool": "benchmarkdotnet", "benches": []}]):
            with self.subTest(history=history):
                with self.assertRaisesRegex(ValueError, "baseline.*net8.0"):
                    baseline.select_suite({"entries": {"Benchmark net8.0": history}}, "net8.0")

    def test_other_benchmark_tool_fails(self):
        with self.assertRaisesRegex(ValueError, "Invalid"):
            baseline.select_suite({"entries": {"Benchmark net8.0": [
                {"tool": "customSmallerIsBetter", "benches": [{"value": 1}]}
            ]}}, "net8.0")

    def test_invalid_framework_fails(self):
        for framework in ("net8.0\nname=Benchmark", "Benchmark", ""):
            with self.assertRaisesRegex(ValueError, "Invalid target framework"):
                baseline.select_suite({}, framework)

    def test_reads_json_without_executing_javascript(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.js"
            path.write_text('window.BENCHMARK_DATA = {"entries": {}};\n')
            self.assertEqual(baseline.read_data(path), {"entries": {}})
            path.write_text('window.BENCHMARK_DATA = {}; process.exit(0);')
            with self.assertRaises(ValueError):
                baseline.read_data(path)

    def test_workflow_uses_only_the_validated_suite_name(self):
        workflow = (SCRIPT_DIR.parent / "workflows" / "perform-benchmarks.yml").read_text()
        self.assertIn("name: ${{ steps.baseline.outputs.name }}", workflow)
        self.assertIn("validate_benchmark_baseline.py", workflow)
        self.assertIn("BENCHMARK_ALERT_THRESHOLD: '105%'", workflow)
        self.assertIn("alert-threshold: ${{ env.BENCHMARK_ALERT_THRESHOLD }}", workflow)
        self.assertIn("fail-on-alert: true", workflow)


if __name__ == "__main__":
    unittest.main()
