"""Local Git fixtures only: no credentials, network, or real gh-pages writes."""

import copy
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from test_prepare_benchmark_comparison import history, identity, report


SCRIPTS = Path(__file__).resolve().parents[1]
SCRIPT = SCRIPTS / "validate_benchmark_publication.py"
WORKFLOW = SCRIPTS.parent / "workflows/perform-benchmarks.yml"
DATA_PATH = "dev/bench/data.js"


class BenchmarkPublicationCommitTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.remote = self.root / "remote.git"
        self.work = self.root / "work"
        self.work.mkdir()
        self.git("init", "--bare", str(self.remote))
        self.git("init", "--initial-branch=source")
        self.git("config", "user.name", "Offline fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.work / "README").write_text("Local fixture\n")
        self.git("add", "README")
        self.git("commit", "-m", "source")
        self.current = self.git("rev-parse", "HEAD").strip()
        self.git("remote", "add", "origin", str(self.remote))
        self.raw = report()
        self.raw["Benchmarks"][0]["Statistics"]["Mean"] = 104
        self.source = self.root / "raw.json"
        self.source.write_text(json.dumps(self.raw))
        self.retained = self.root / "retained.js"
        self.write_data(self.retained, history())

    def git(self, *args, check=True):
        result = subprocess.run(["git", *args], cwd=self.work, capture_output=True, text=True)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        return result

    @staticmethod
    def write_data(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        # Match the pinned action, which does not accept a trailing semicolon.
        path.write_text("window.BENCHMARK_DATA = " + json.dumps(data))

    def candidate(self, parent_value=100, mutate_parent=None, mutate_candidate=None):
        self.git("switch", "-c", "gh-pages")
        parent = history()
        parent["entries"]["Benchmark net10.0"][0]["benches"][0]["value"] = parent_value
        if mutate_parent:
            mutate_parent(parent)
        self.write_data(self.work / DATA_PATH, parent)
        self.git("add", DATA_PATH)
        self.git("commit", "-m", "history used by action")
        self.parent = self.git("rev-parse", "HEAD").strip()
        self.git("push", "origin", "gh-pages")
        data = copy.deepcopy(parent)
        data["lastUpdate"] = 123
        data["repoUrl"] = "https://example.invalid/offline"
        data["entries"]["Benchmark net10.0"].append({
            "commit": {"id": self.current}, "tool": "benchmarkdotnet", "benches": [
                {"name": identity(n), "value": row["Statistics"]["Mean"], "unit": "ns"}
                for n, row in zip([10, 3], self.raw["Benchmarks"])
            ]})
        if mutate_candidate:
            mutate_candidate(data)
        self.write_data(self.work / DATA_PATH, data)
        self.git("add", DATA_PATH)
        self.git("commit", "-m", "locally prepared result")
        candidate = self.git("rev-parse", "HEAD").strip()
        self.git("switch", "source")
        return candidate

    def validate(self):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.retained), "net10.0",
                               str(self.source), self.current, "105%"], cwd=self.work,
                              capture_output=True, text=True)

    def remote_tip(self):
        return self.git("ls-remote", "origin", "refs/heads/gh-pages").split()[0]

    def publish(self, commit):
        workflow = WORKFLOW.read_text()
        steps = re.findall(r"^    - name:.*?(?=^    - name:|\Z)", workflow, re.MULTILINE | re.DOTALL)
        step = next((s for s in steps if "id: publishbenchmark\n" in s), None)
        self.assertIsNotNone(step, "Publication must be a separate success-only step")
        self.assertIn("if: success() && github.event_name == 'push' && github.ref == 'refs/heads/main'", step)
        self.assertIn("VERIFIED_COMMIT: ${{ steps.publication.outputs.commit }}", step)
        run = re.search(r"^      run: \|\n((?:        .*\n|\n)+)", step, re.MULTILINE)
        self.assertIsNotNone(run)
        return subprocess.run(["bash", "-e", "-o", "pipefail", "-c", textwrap.dedent(run[1])],
                              cwd=self.work, env={**os.environ, "VERIFIED_COMMIT": commit},
                              capture_output=True, text=True)

    def test_upstream_action_cannot_publish_before_its_alerts(self):
        workflow = WORKFLOW.read_text()
        self.assertRegex(workflow, r"(?m)^        auto-push: false$")
        self.assertIn("        fail-on-alert: true", workflow)

    def workflow_reported_commit(self, event_sha, pr_head=None):
        steps = re.findall(r"^    - name:.*?(?=^    - name:|\Z)", WORKFLOW.read_text(),
                           re.MULTILINE | re.DOTALL)
        action = next(step for step in steps if "id: storebenchmark\n" in step)
        ref = re.search(r"(?m)^        ref: \$\{\{ (.*?) \}\}$", action)
        self.assertIsNotNone(ref)
        # Resolve the actual action input using these two documented event values.
        # This is an offline context fixture, not an execution of the hosted action.
        values = {"github.sha": event_sha, "github.event.pull_request.head.sha": pr_head}
        terms = [term.strip() for term in ref[1].split("||")]
        self.assertTrue(all(term in values for term in terms), ref[1])
        return next(values[term] for term in terms if values[term])

    def assert_workflow_report_validates(self, event_sha, pr_head=None):
        reported = self.workflow_reported_commit(event_sha, pr_head)
        candidate = self.candidate(mutate_candidate=lambda data: data["entries"]["Benchmark net10.0"][-1]
                                   ["commit"].update(id=reported))
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"commit={candidate}\n")
        self.assertEqual(self.remote_tip(), self.parent)

    def test_pr_action_reports_head_not_synthetic_merge_commit(self):
        self.git("commit", "--allow-empty", "-m", "synthetic PR merge")
        merge_sha = self.git("rev-parse", "HEAD").strip()
        self.assertNotEqual(merge_sha, self.current)
        self.assert_workflow_report_validates(merge_sha, pr_head=self.current)

    def test_push_action_reports_event_commit(self):
        self.assert_workflow_report_validates(self.current)

    def test_dispatch_action_reports_pinned_event_commit_when_branch_moves(self):
        self.git("commit", "--allow-empty", "-m", "branch moved after dispatch")
        self.assertNotEqual(self.git("rev-parse", "HEAD").strip(), self.current)
        self.assert_workflow_report_validates(self.current)

    def test_publication_follows_all_gates_and_never_runs_for_pr_or_dispatch(self):
        workflow = WORKFLOW.read_text()
        steps = re.findall(r"^    - name:.*?(?=^    - name:|\Z)", workflow, re.MULTILINE | re.DOTALL)
        positions = []
        for marker in ("id: comparison\n", "id: storebenchmark\n", "name: Enforce verified snapshot",
                       "id: publication\n", "id: publishbenchmark\n"):
            position = next(i for i, step in enumerate(steps) if marker in step)
            positions.append(position)
            self.assertNotIn("continue-on-error", steps[position])
        self.assertEqual(positions, sorted(positions))
        self.assertNotRegex(steps[positions[3]], r"(?m)^      if:")
        self.assertIn("if: success() && github.event_name == 'push' && github.ref == 'refs/heads/main'",
                      steps[positions[4]])
        self.assertIn("max-parallel: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && 1 || 3 }}",
                      workflow)

    def test_stale_snapshot_pass_does_not_publish_against_stricter_actual_parent(self):
        self.candidate(parent_value=90)
        # The earlier snapshot gate genuinely passes 104 against 100.
        before = subprocess.run([sys.executable, str(SCRIPTS / "prepare_benchmark_comparison.py"),
                                 str(self.retained), "net10.0", str(self.source),
                                 str(self.root / "comparison.json"), self.current, "--check", "105%"],
                                capture_output=True, text=True)
        self.assertEqual(before.returncode, 0, before.stderr)
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Performance regression against verified snapshot", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)

    def test_retained_snapshot_is_not_replaced_by_more_permissive_parent(self):
        self.raw["Benchmarks"][0]["Statistics"]["Mean"] = 108
        self.source.write_text(json.dumps(self.raw))
        self.candidate(parent_value=110)
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Performance regression against verified snapshot", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)

    def test_valid_commit_publishes_exact_validated_sha(self):
        candidate = self.candidate()
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"commit={candidate}\n")
        self.assertEqual(self.remote_tip(), self.parent)
        # Moving the local branch after validation cannot change the published SHA.
        self.git("branch", "-f", "gh-pages", "source")
        push = self.publish(candidate)
        self.assertEqual(push.returncode, 0, push.stderr)
        self.assertEqual(self.remote_tip(), candidate)

    def test_workflow_validation_shell_outputs_only_the_checked_commit(self):
        candidate = self.candidate()
        scripts = self.work / ".github/scripts"
        scripts.mkdir(parents=True)
        for name in ("validate_benchmark_publication.py", "prepare_benchmark_comparison.py", "validate_benchmark_baseline.py"):
            shutil.copyfile(SCRIPTS / name, scripts / name)
        reports = self.work / "benchmarks/HeroSdJwt.Benchmarks/BenchmarkDotNet.Artifacts/results"
        reports.mkdir(parents=True)
        shutil.copyfile(self.source, reports / "combined-report-net10.0.json")
        shutil.copyfile(self.retained, self.root / "benchmark-baseline.js")
        output = self.root / "github-output"
        steps = re.findall(r"^    - name:.*?(?=^    - name:|\Z)", WORKFLOW.read_text(), re.MULTILINE | re.DOTALL)
        step = next(s for s in steps if "id: publication\n" in s)
        run = re.search(r"^      run: \|\n((?:        .*\n|\n)+)", step, re.MULTILINE)
        self.assertIsNotNone(run)
        result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", textwrap.dedent(run[1])], cwd=self.work,
                                env={**os.environ, "FRAMEWORK": "net10.0", "CURRENT_COMMIT": self.current,
                                     "RUNNER_TEMP": str(self.root), "BENCHMARK_ALERT_THRESHOLD": "105%",
                                     "GITHUB_OUTPUT": str(output)}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), f"commit={candidate}\n")
        self.assertEqual(self.remote_tip(), self.parent)

    def test_concurrent_forward_update_rejects_publication_without_retry(self):
        candidate = self.candidate()
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.git("switch", "-c", "competitor", self.parent)
        (self.work / "competitor").write_text("A newer history publisher won\n")
        self.git("add", "competitor")
        self.git("commit", "-m", "concurrent remote update")
        competing = self.git("rev-parse", "HEAD").strip()
        self.git("push", "origin", "HEAD:refs/heads/gh-pages")
        self.git("switch", "source")
        push = self.publish(candidate)
        self.assertNotEqual(push.returncode, 0)
        self.assertIn("rejected", push.stderr)
        self.assertEqual(self.remote_tip(), competing)

    def test_rejects_ambiguous_actual_parent(self):
        def duplicate(data):
            data["entries"]["Benchmark net10.0"][0]["benches"][1]["name"] = identity(10)
        self.candidate(mutate_parent=duplicate)
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ambiguous baseline job identity", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)

    def test_rejects_candidate_not_matching_raw_result(self):
        self.candidate(mutate_candidate=lambda d: d["entries"]["Benchmark net10.0"][-1]["benches"][0].update(value=1))
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Prepared result differs from raw measurements", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)

    def test_rejects_wrong_current_commit(self):
        self.candidate(mutate_candidate=lambda d: d["entries"]["Benchmark net10.0"][-1]["commit"].update(id="wrong"))
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Prepared result has the wrong commit or tool", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)

    def test_rejects_duplicate_result_identity(self):
        def duplicate(data):
            benches = data["entries"]["Benchmark net10.0"][-1]["benches"]
            benches[1] = copy.deepcopy(benches[0])
        self.candidate(mutate_candidate=duplicate)
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Prepared result differs from raw measurements", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)

    @staticmethod
    def node_roundtrip(data):
        # The action reads and writes all numeric leaves through JavaScript Number.
        result = subprocess.run(["node", "-e",
                                 "process.stdout.write(JSON.stringify(JSON.parse(require('fs').readFileSync(0,'utf8'))))"],
                                input=json.dumps(data), capture_output=True, text=True, check=True)
        data.clear()
        data.update(json.loads(result.stdout))

    def test_accepts_exact_node_double_representation_of_current_mean(self):
        self.raw["Benchmarks"][0]["Statistics"]["Mean"] = 1.0000000000000001e18
        self.source.write_text(json.dumps(self.raw))
        saved = history()
        saved["entries"]["Benchmark net10.0"][0]["benches"][0]["value"] = 1e18
        self.write_data(self.retained, saved)
        self.candidate(parent_value=1e18, mutate_candidate=self.node_roundtrip)
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_exact_node_double_representation_of_existing_history(self):
        value = 1.0000000000000001e18
        self.raw["Benchmarks"][0]["Statistics"]["Mean"] = value
        self.source.write_text(json.dumps(self.raw))
        saved = history()
        saved["entries"]["Benchmark net10.0"][0]["benches"][0]["value"] = value
        self.write_data(self.retained, saved)
        self.candidate(parent_value=value, mutate_candidate=self.node_roundtrip)
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_history_boolean_is_not_equivalent_to_numeric_one(self):
        self.candidate(mutate_parent=lambda d: d["entries"]["Benchmark net10.0"][0].update(marker=True),
                       mutate_candidate=lambda d: d["entries"]["Benchmark net10.0"][0].update(marker=1))
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Prepared commit must preserve history", result.stderr)

    def test_different_adjacent_double_is_not_accepted_with_tolerance(self):
        self.candidate(mutate_candidate=lambda d: d["entries"]["Benchmark net10.0"][-1]["benches"][0].update(
            value=math.nextafter(104, math.inf)))
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Prepared result differs from raw measurements", result.stderr)

    def test_rejects_other_framework_history_changes(self):
        def add_framework(data):
            data["entries"]["Benchmark net8.0"] = copy.deepcopy(data["entries"]["Benchmark net10.0"])
        self.candidate(mutate_parent=add_framework,
                       mutate_candidate=lambda d: d["entries"]["Benchmark net8.0"].clear())
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Prepared commit must preserve history", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)

    def test_rejects_extra_appended_result(self):
        self.candidate(mutate_candidate=lambda d: d["entries"]["Benchmark net10.0"].append(
            copy.deepcopy(d["entries"]["Benchmark net10.0"][-1])))
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Prepared commit must preserve history", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)

    def test_accepts_action_creating_missing_default_index(self):
        self.candidate()
        self.git("switch", "gh-pages")
        (self.work / "dev/bench/index.html").write_text("Default chart\n")
        self.git("add", "dev/bench/index.html")
        self.git("commit", "--amend", "--no-edit")
        candidate = self.git("rev-parse", "HEAD").strip()
        self.git("switch", "source")
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"commit={candidate}\n")

    def test_rejects_replacement_of_existing_index(self):
        def existing_index(_):
            path = self.work / "dev/bench/index.html"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Existing chart\n")
            self.git("add", "dev/bench/index.html")
        self.candidate(mutate_parent=existing_index)
        self.git("switch", "gh-pages")
        (self.work / "dev/bench/index.html").write_text("Unexpected replacement\n")
        self.git("add", "dev/bench/index.html")
        self.git("commit", "--amend", "--no-edit")
        self.git("switch", "source")
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Prepared commit must not replace an existing index", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)

    def test_rejects_deleted_history(self):
        self.candidate(mutate_candidate=lambda d: d["entries"]["Benchmark net10.0"].pop(0))
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Prepared commit must preserve history", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)

    def test_rejects_unrelated_file_changes(self):
        self.candidate()
        self.git("switch", "gh-pages")
        (self.work / "README").write_text("Unexpected overwrite\n")
        self.git("add", "README")
        self.git("commit", "--amend", "--no-edit")
        self.git("switch", "source")
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unexpected prepared commit files", result.stderr)
        self.assertEqual(self.remote_tip(), self.parent)


if __name__ == "__main__":
    unittest.main()
