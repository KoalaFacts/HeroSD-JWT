"""Historical data availability must not hide real failures or block delivery."""

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / "workflows/perform-benchmarks.yml"


class OptionalBenchmarkHistoryTests(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.steps = re.findall(r"^    - name:.*?(?=^    - name:|\Z)",
                                self.workflow, re.MULTILINE | re.DOTALL)

    def step(self, name):
        return next(step for step in self.steps if step.startswith(f"    - name: {name}"))

    def test_only_historical_baseline_errors_are_nonblocking(self):
        baseline = self.step("Validate framework-specific benchmark baseline")
        self.assertIn("      continue-on-error: true\n", baseline)
        self.assertEqual(self.workflow.count("continue-on-error:"), 1)
        self.assertLess(self.workflow.index("Collect complete current benchmark evidence"),
                        self.workflow.index("Validate framework-specific benchmark baseline"))

    def test_comparison_requires_a_valid_baseline_and_previous_success(self):
        comparison = self.step("Validate job identities and snapshot performance before storage")
        self.assertIn("      if: success() && steps.baseline.outcome == 'success'\n", comparison)
        self.assertNotIn("continue-on-error", comparison)
        self.assertIn('--check "$BENCHMARK_ALERT_THRESHOLD"', comparison)
        self.assertIn("BENCHMARK_ALERT_THRESHOLD: '105%'", self.workflow)

    def test_no_storage_or_publication_after_an_inconclusive_comparison(self):
        storage = self.step("Prepare local benchmark result")
        publication = self.step("Validate prepared benchmark commit")
        push = self.step("Publish verified benchmark commit")
        self.assertIn("      if: success() && steps.comparison.outcome == 'success'\n", storage)
        self.assertIn("      if: success() && steps.storebenchmark.outcome == 'success'\n", publication)
        self.assertIn("steps.publication.outcome == 'success'", push)
        self.assertIn("github.event_name == 'push'", push)
        self.assertIn("github.ref == 'refs/heads/main'", push)
        self.assertIn("fail-on-alert: true", storage)
        self.assertIn("auto-push: false", storage)
        for step in (storage, publication, push):
            self.assertNotIn("continue-on-error", step)

    def test_warning_records_inconclusive_not_performance_pass(self):
        warning = self.step("Report unavailable historical comparison")
        self.assertIn("      if: always() && steps.baseline.outcome == 'failure'\n", warning)
        run = re.search(r"^      run: \|\n((?:        .*\n|\n)+)", warning, re.MULTILINE)
        self.assertIsNotNone(run)
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            result = subprocess.run(
                ["bash", "-e", "-o", "pipefail", "-c", textwrap.dedent(run[1])],
                env={**os.environ, "FRAMEWORK": "net10.0", "GITHUB_STEP_SUMMARY": str(summary)},
                capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("::warning::", result.stdout)
            self.assertIn("INCONCLUSIVE", result.stdout)
            self.assertIn("net10.0", summary.read_text())
            self.assertIn("not a performance pass", summary.read_text())

    def test_measurement_and_current_evidence_failures_remain_blocking(self):
        for name in ("Test benchmark evidence validation", "Restore dependencies",
                     "Build benchmarks", "Run benchmarks", "Collect complete current benchmark evidence"):
            with self.subTest(step=name):
                step = self.step(name)
                self.assertNotIn("continue-on-error", step)
                self.assertNotIn("|| true", step)
        self.assertIn("      if: always()\n", self.step("Upload benchmark artifacts"))

    def test_verified_snapshot_gate_still_runs_when_comparison_succeeds(self):
        gate = self.step("Enforce verified snapshot performance gate")
        self.assertIn("if: always() && steps.comparison.outcome == 'success'", gate)
        self.assertIn('--check "$BENCHMARK_ALERT_THRESHOLD"', gate)
        self.assertNotIn("continue-on-error", gate)


if __name__ == "__main__":
    unittest.main()
