import re
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[3]
ARTIFACT_ROOT = "benchmarks/HeroSdJwt.Benchmarks/BenchmarkDotNet.Artifacts"


class BenchmarkArtifactTests(unittest.TestCase):
    def setUp(self):
        workflow = (REPOSITORY / ".github/workflows/perform-benchmarks.yml").read_text()
        match = re.search(
            r"^    - name: Upload benchmark artifacts.*?(?=^    - name:|\Z)",
            workflow,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, "Benchmark artifact upload step is missing")
        self.upload = match.group()

    def test_upload_runs_after_success_or_failure_without_action_outputs(self):
        self.assertRegex(self.upload, r"(?m)^      if: always\(\)$")
        self.assertNotIn("steps.storebenchmark.outputs", self.upload)

    def test_upload_selects_raw_json_and_logs_directly(self):
        match = re.search(r"(?m)^        path: \|\n((?:          .+\n)+)", self.upload)
        self.assertIsNotNone(match, "Upload must declare concrete artifact paths")
        patterns = [line.strip() for line in match.group(1).splitlines()]
        self.assertEqual(patterns, [
            f"{ARTIFACT_ROOT}/*.log",
            f"{ARTIFACT_ROOT}/results/*.json",
        ])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = {
                f"{ARTIFACT_ROOT}/HeroSdJwt.Benchmarks.IssuanceBenchmarks.log",
                f"{ARTIFACT_ROOT}/results/IssuanceBenchmarks-report-full.json",
                f"{ARTIFACT_ROOT}/results/PresentationBenchmarks-report-full-compressed.json",
                f"{ARTIFACT_ROOT}/results/combined-report-net10.0.json",
            }
            excluded = {
                ".git/config",
                ".github/secrets.json",
                "benchmarks/HeroSdJwt.Benchmarks/bin/Release/credentials.json",
                f"{ARTIFACT_ROOT}/generated/bin/build.log",
            }
            for name in expected | excluded:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture")
            selected = {
                str(path.relative_to(root))
                for pattern in patterns
                for path in root.glob(pattern)
            }
            self.assertEqual(selected, expected)

    def test_retention_hidden_file_exclusion_and_framework_isolation_remain(self):
        self.assertIn("retention-days: 30", self.upload)
        self.assertIn("include-hidden-files: false", self.upload)
        self.assertIn("name: benchmark-results-${{ matrix.framework }}", self.upload)

    def test_absent_artifacts_do_not_hide_the_original_failure(self):
        self.assertIn("if-no-files-found: warn", self.upload)
        self.assertNotIn("continue-on-error", self.upload)


if __name__ == "__main__":
    unittest.main()
