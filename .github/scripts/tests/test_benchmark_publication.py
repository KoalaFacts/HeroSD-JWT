import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from test_prepare_benchmark_comparison import history, report


SCRIPT_DIR = Path(__file__).resolve().parents[1]


class BenchmarkPublicationTests(unittest.TestCase):
    def test_workflow_checks_snapshot_threshold_before_storage(self):
        workflow = (SCRIPT_DIR.parent / "workflows/perform-benchmarks.yml").read_text()
        steps = re.findall(r"^    - name:.*?(?=^    - name:|\Z)", workflow,
                           re.MULTILINE | re.DOTALL)
        comparison = next(step for step in steps if "id: comparison\n" in step)
        storage = next(step for step in steps if "id: storebenchmark\n" in step)
        self.assertLess(steps.index(comparison), steps.index(storage))
        self.assertNotIn("continue-on-error", comparison)
        # The storage action must retain GitHub's default success-only condition.
        self.assertNotRegex(storage, r"(?m)^      if:")
        run = re.search(r"^      run: \|\n((?:        .*\n|\n)+)", comparison, re.MULTILINE)
        self.assertIsNotNone(run)
        command = textwrap.dedent(run[1])

        for mean, passes in [(100, True), (105, True), (105.00001, False), (200, False)]:
            with self.subTest(mean=mean), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                scripts = root / ".github/scripts"
                scripts.mkdir(parents=True)
                for filename in ("prepare_benchmark_comparison.py", "validate_benchmark_baseline.py"):
                    shutil.copyfile(SCRIPT_DIR / filename, scripts / filename)
                baseline = root / "benchmark-baseline.js"
                baseline.write_text("window.BENCHMARK_DATA = " + json.dumps(history()) + ";\n")
                reports = root / "benchmarks/HeroSdJwt.Benchmarks/BenchmarkDotNet.Artifacts/results"
                reports.mkdir(parents=True)
                raw = report()
                raw["Benchmarks"][0]["Statistics"]["Mean"] = mean
                source = reports / "combined-report-net10.0.json"
                source.write_text(json.dumps(raw))
                before = [path.read_bytes() for path in (baseline, source)]
                # Execute the actual pre-storage workflow shell, not a parallel implementation.
                # No GitHub action, network request, timing workload or storage is executed.
                result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", command], cwd=root,
                                        env={**os.environ, "FRAMEWORK": "net10.0", "CURRENT_COMMIT": "current",
                                             "RUNNER_TEMP": str(root), "BENCHMARK_ALERT_THRESHOLD": "105%"},
                                        capture_output=True, text=True)
                self.assertEqual(before, [path.read_bytes() for path in (baseline, source)])
                if passes:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, "A regression must fail before storage can run")
                    self.assertIn("Performance regression against verified snapshot", result.stderr)


if __name__ == "__main__":
    unittest.main()
