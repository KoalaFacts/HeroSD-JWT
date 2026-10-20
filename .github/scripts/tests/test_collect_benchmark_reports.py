import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIR))
SPEC = importlib.util.spec_from_file_location('collector', SCRIPT_DIR / 'collect_benchmark_reports.py')
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def fixtures():
    methods = {
        'IssuanceBenchmarks': [(f'IssueWith{algorithm}', f'claimCount={count}')
                               for algorithm in ('Hmac', 'Rsa', 'Ecdsa') for count in (10, 50, 100)],
        'PresentationBenchmarks': [(f'CreatePresentation{suffix}', '') for suffix in
                                   ('AllClaims', 'FewClaims', 'ManyClaims', 'WithKeyBinding')],
        'VerificationBenchmarks': [(method, '') for method in
                                   ('VerifyWithoutKeyBinding', 'VerifyWithKeyBinding', 'TryVerifyWithoutKeyBinding')],
    }
    reports = {}
    for type_name, cases in methods.items():
        rows = []
        for method, parameters in cases:
            name = f'HeroSdJwt.Benchmarks.{type_name}.{method}'
            if parameters:
                name += '(' + parameters.replace('=', ': ') + ')'
            for job, count in [('Job-ABCDEF', 10), ('ShortRun', 3)]:
                display = f'{type_name}.{method}: {job}(IterationCount={count}, LaunchCount=1, WarmupCount=3)'
                if parameters:
                    display += f' [{parameters}]'
                rows.append(dict(Namespace='HeroSdJwt.Benchmarks', Type=type_name, Method=method,
                                 Parameters=parameters, FullName=name, DisplayInfo=display,
                                 Statistics={'Mean': 100, 'StandardDeviation': 1, 'N': count - 1},
                                 Measurements=[{'Nanoseconds': 100, 'Operations': 1}],
                                 Memory={'BytesAllocatedPerOperation': 20}))
        reports[f'HeroSdJwt.Benchmarks.{type_name}-report-full-compressed.json'] = {
            'Title': type_name + '-timestamp',
            'HostEnvironmentInfo': {'BenchmarkDotNetVersion': '0.15.8', 'RuntimeVersion': '.NET 10.0.13 (x)',
                                    'DotNetCliVersion': '10.0.402'}, 'Benchmarks': rows}
    return reports


class CurrentReportTests(unittest.TestCase):
    def collect(self, reports=None, framework='net10.0'):
        reports = fixtures() if reports is None else reports
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in reports.items():
                (root / name).write_text(json.dumps(data))
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            result = collector.collect_reports(root, framework, 'a' * 40, 'b' * 40)
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})
            return result, before

    def test_preserves_all_32_rows_and_binds_each_to_exact_source_hash(self):
        (combined, manifest), raw = self.collect()
        self.assertEqual(len(combined['Benchmarks']), 32)
        expected = [row for name, data in sorted(fixtures().items()) for row in data['Benchmarks']]
        self.assertEqual(combined['Benchmarks'], expected)
        self.assertEqual(len({row['fullname'] for row in manifest['rows']}), 16)
        self.assertEqual({row['iteration_count'] for row in manifest['rows']}, {3, 10})
        self.assertEqual(manifest['source_revision'], 'a' * 40)
        self.assertEqual(manifest['source_tree'], 'b' * 40)
        self.assertEqual(manifest['unit'], 'ns')
        self.assertTrue(manifest['current_report_complete'])
        self.assertEqual(manifest['historical_coverage'], 'historical_coverage_unverified')
        self.assertFalse(manifest['historical_acceptance_passed'])
        self.assertEqual({r['file']: r['sha256'] for r in manifest['reports']},
                         {name: hashlib.sha256(content).hexdigest() for name, content in raw.items()})
        for row in manifest['rows']:
            self.assertEqual(row['raw_report_sha256'], hashlib.sha256(raw[row['file']]).hexdigest())
        self.assertEqual(manifest['combined_sha256'], hashlib.sha256(collector.encode(combined)).hexdigest())

    def test_rejects_missing_extra_and_duplicate_report_files(self):
        for change in ('missing', 'extra', 'duplicate'):
            reports = fixtures()
            name = next(iter(reports))
            if change == 'missing':
                del reports[name]
            else:
                target = name.replace('full-compressed', 'full') if change == 'duplicate' else 'Unknown-report-full.json'
                reports[target] = copy.deepcopy(reports[name])
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'file set'):
                self.collect(reports)

    def test_rejects_incomplete_extra_duplicate_and_unknown_cases(self):
        for change in ('missing', 'extra', 'duplicate_job', 'unknown', 'wrong_file'):
            reports = fixtures()
            rows = next(iter(reports.values()))['Benchmarks']
            if change == 'missing':
                rows.pop()
            elif change == 'extra':
                rows.append(copy.deepcopy(rows[0]))
            elif change == 'duplicate_job':
                rows[1] = copy.deepcopy(rows[0])
            elif change == 'unknown':
                rows[0]['FullName'] = 'Unexpected.Method'
            else:
                other = list(reports.values())[1]['Benchmarks']
                rows[0], other[0] = other[0], rows[0]
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.collect(reports)

    def test_rejects_unknown_or_inconsistent_job_identity(self):
        for display in ('NewJob(IterationCount=10, LaunchCount=1, WarmupCount=3)',
                        'ShortRun(IterationCount=10, LaunchCount=1, WarmupCount=3)',
                        'Job-ABCDEF(IterationCount=10, LaunchCount=2, WarmupCount=3)'):
            reports = fixtures()
            row = next(iter(reports.values()))['Benchmarks'][0]
            row['DisplayInfo'] = 'IssuanceBenchmarks.IssueWithHmac: ' + display + ' [claimCount=10]'
            with self.subTest(display=display), self.assertRaises(ValueError):
                self.collect(reports)

    def test_rejects_metadata_identity_disagreement(self):
        for field, value in [('Type', 'Other'), ('Method', 'Other'), ('Parameters', 'claimCount=50'),
                             ('Namespace', 'Other'), ('DisplayInfo', 'Wrong.Method: ShortRun(IterationCount=3, LaunchCount=1, WarmupCount=3)')]:
            reports = fixtures()
            next(iter(reports.values()))['Benchmarks'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.collect(reports)

    def test_rejects_wrong_framework_host_or_exporter(self):
        for field, value in [('RuntimeVersion', '.NET 9.0.21 (x)'), ('DotNetCliVersion', 'different'),
                             ('BenchmarkDotNetVersion', '0.15.9')]:
            reports = fixtures()
            next(iter(reports.values()))['HostEnvironmentInfo'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.collect(reports)
        with self.assertRaises(ValueError):
            self.collect(framework='net9.0')

    def test_rejects_nonfinite_or_invalid_measurements(self):
        for field in ('Mean', 'StandardDeviation'):
            for value in (float('nan'), float('inf'), -1, True, None, '100'):
                reports = fixtures()
                next(iter(reports.values()))['Benchmarks'][0]['Statistics'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.collect(reports)
        reports = fixtures()
        next(iter(reports.values()))['Benchmarks'][0]['Measurements'][0]['Nanoseconds'] = float('nan')
        with self.assertRaises(ValueError):
            self.collect(reports)

    def test_rejects_wrong_explicit_unit(self):
        for location in ('report', 'row', 'statistics'):
            reports = fixtures()
            data = next(iter(reports.values()))
            target = data if location == 'report' else data['Benchmarks'][0]
            if location == 'statistics':
                target = target['Statistics']
            target['Unit'] = 'us'
            with self.subTest(location=location), self.assertRaises(ValueError):
                self.collect(reports)

    def test_rejects_missing_raw_measurements_and_source_hashes(self):
        reports = fixtures()
        next(iter(reports.values()))['Benchmarks'][0]['Measurements'] = []
        with self.assertRaises(ValueError):
            self.collect(reports)
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            collector.collect_reports(Path(directory), 'net10.0', 'unknown', 'b' * 40)

    def test_cli_publishes_only_after_validation_and_never_replaces_raw(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = fixtures()
            for name, data in reports.items():
                (root / name).write_text(json.dumps(data))
            command = [sys.executable, str(SCRIPT_DIR / 'collect_benchmark_reports.py'), str(root),
                       'net10.0', 'a' * 40, 'b' * 40]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / 'combined-report-net10.0.json').exists())
            self.assertTrue((root / 'current-evidence-net10.0.json').exists())
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, 'Do not overwrite a previous evidence bundle')

    def test_workflow_collects_before_history_without_allowing_failed_history_to_store(self):
        workflow = (SCRIPT_DIR.parent / 'workflows/perform-benchmarks.yml').read_text()
        self.assertLess(workflow.index('collect_benchmark_reports.py'), workflow.index('id: baseline'))
        self.assertNotIn('continue-on-error', workflow)
        self.assertNotIn("jq -s", workflow)
        self.assertIn('timeout-minutes: 60', workflow)
        self.assertIn('git rev-parse HEAD^{tree}', workflow)
        self.assertLess(workflow.index('id: baseline'), workflow.index('id: comparison'))
        self.assertLess(workflow.index('id: comparison'), workflow.index('id: storebenchmark'))


if __name__ == '__main__':
    unittest.main()
