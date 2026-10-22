"""Retain complete current BDN evidence, independently of historical acceptance.

The pinned BDN JSON exporter writes Statistics and Measurements.Nanoseconds in ns.
A report manifest binds every configured case to its original file bytes. It does
not recover missing historical provenance or prove a performance gate passed.
"""

import copy
import hashlib
import json
import math
import re
import sys
from pathlib import Path

from prepare_benchmark_comparison import job_identity, numeric_value

PREFIX = "HeroSdJwt.Benchmarks."
CASES = {
    "IssuanceBenchmarks": {
        f"IssueWith{algorithm}(claimCount: {count})"
        for algorithm in ("Hmac", "Rsa", "Ecdsa") for count in (10, 50, 100)
    },
    "PresentationBenchmarks": {
        f"CreatePresentation{suffix}"
        for suffix in ("AllClaims", "FewClaims", "ManyClaims", "WithKeyBinding")
    },
    "VerificationBenchmarks": {
        "VerifyWithoutKeyBinding", "VerifyWithKeyBinding", "TryVerifyWithoutKeyBinding"
    },
}


def encode(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def validate_numbers(value):
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Non-finite number in raw report")
    if isinstance(value, dict):
        for item in value.values():
            validate_numbers(item)
    elif isinstance(value, list):
        for item in value:
            validate_numbers(item)


def validate_row(row, type_name):
    name = row.get("FullName")
    method = row.get("Method")
    parameters = row.get("Parameters")
    if not isinstance(method, str) or not isinstance(parameters, str):
        raise ValueError("Missing raw benchmark method/parameters")
    declared_name = f"{PREFIX}{type_name}.{method}"
    if parameters:
        declared_name += "(" + parameters.replace("=", ": ") + ")"
    display = row.get("DisplayInfo", "")
    if (row.get("Namespace") != PREFIX.rstrip(".") or row.get("Type") != type_name
            or name != declared_name or not display.startswith(f"{type_name}.{method}: ")
            or (parameters and not display.endswith(f" [{parameters}]"))
            or (not parameters and " [" in display)):
        raise ValueError(f"Inconsistent benchmark metadata identity: {name}")
    identity, iterations = job_identity(row)
    statistics = row.get("Statistics")
    if not isinstance(statistics, dict):
        raise ValueError(f"Missing benchmark statistics: {identity}")
    for value in (row, statistics):
        if value.get("Unit", "ns") != "ns":
            raise ValueError("Unsupported benchmark unit")
    for field in ("Mean", "StandardDeviation"):
        numeric_value(statistics.get(field), identity)
    measurements = row.get("Measurements")
    if not isinstance(measurements, list) or not measurements:
        raise ValueError(f"Missing raw measurements: {identity}")
    for measurement in measurements:
        numeric_value(measurement.get("Nanoseconds"), identity)
        operations = measurement.get("Operations")
        if type(operations) is not int or operations <= 0:
            raise ValueError(f"Invalid raw operation count: {identity}")
    # BDN ResultStatistics uses Workload/Result, after its own outlier removal
    # and overhead adjustment. Do not substitute the configured iteration count.
    results = [measurement for measurement in measurements
               if measurement.get("IterationMode") == "Workload"
               and measurement.get("IterationStage") == "Result"]
    if not results:
        raise ValueError(f"Missing workload result measurements: {identity}")
    sample_count = statistics.get("N")
    if type(sample_count) is not int or sample_count != len(results):
        raise ValueError(f"Statistics sample count differs from workload results: {identity}")
    return identity, iterations


def collect_reports(directory, framework, source_revision, source_tree):
    if framework not in {"net8.0", "net9.0", "net10.0"}:
        raise ValueError(f"Unsupported benchmark framework: {framework}")
    for value in (source_revision, source_tree):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise ValueError("Missing full source revision/tree hash")
    directory = Path(directory)
    paths = sorted(directory.glob("*-report-full*.json"))
    by_type = {}
    for path in paths:
        match = re.fullmatch(r"HeroSdJwt\.Benchmarks\.(\w+)-report-full(?:-compressed)?\.json", path.name)
        if (path.is_symlink() or not path.is_file() or match is None
                or match[1] not in CASES or match[1] in by_type):
            raise ValueError(f"Unexpected or duplicate raw report file set: {path.name}")
        by_type[match[1]] = path
    if set(by_type) != set(CASES):
        raise ValueError("Incomplete raw report file set")
    host = None
    combined = None
    manifest = dict(schema="hero-jwt-current-evidence-v1", framework=framework, unit="ns",
                    source_revision=source_revision, source_tree=source_tree,
                    current_report_complete=True,
                    historical_coverage="historical_coverage_unverified",
                    historical_acceptance_passed=False, reports=[], rows=[])
    for type_name, path in sorted(by_type.items()):
        raw = path.read_bytes()
        report = json.loads(raw)
        validate_numbers(report)
        current_host = report.get("HostEnvironmentInfo")
        runtime_pattern = r"\.NET " + re.escape(framework[3:]) + r"\.\d+(?: \(.+\))?"
        if (not isinstance(current_host, dict)
                or current_host.get("BenchmarkDotNetVersion") != "0.15.8"
                or re.fullmatch(runtime_pattern, current_host.get("RuntimeVersion", "")) is None
                or report.get("Unit", "ns") != "ns"):
            raise ValueError(f"Unsupported exporter, framework or unit: {path.name}")
        if host is not None and host != current_host:
            raise ValueError("Host metadata differs between raw reports")
        host = current_host
        if combined is None:
            combined = copy.deepcopy(report)
            combined["Benchmarks"] = []
        rows = report.get("Benchmarks")
        if not isinstance(rows, list):
            raise ValueError("Missing raw Benchmarks array")
        expected = {(f"{PREFIX}{type_name}.{case}", iterations)
                    for case in CASES[type_name] for iterations in (3, 10)}
        seen = set()
        raw_hash = digest(raw)
        for row in rows:
            identity, iterations = validate_row(row, type_name)
            key = row["FullName"], iterations
            if key not in expected or key in seen:
                raise ValueError(f"Unexpected or duplicate current case identity: {identity}")
            seen.add(key)
            manifest["rows"].append(dict(fullname=key[0], iteration_count=iterations,
                                         launch_count=1, warmup_count=3, file=path.name,
                                         raw_report_sha256=raw_hash))
        if seen != expected:
            raise ValueError(f"Incomplete current case identity set: {path.name}")
        combined["Benchmarks"].extend(copy.deepcopy(rows))
        manifest["reports"].append(dict(file=path.name, sha256=raw_hash, rows=len(rows)))
    manifest["host_environment"] = copy.deepcopy(host)
    manifest["combined_sha256"] = digest(encode(combined))
    return combined, manifest


if __name__ == "__main__":
    try:
        if len(sys.argv) != 5:
            raise ValueError("Usage: collect_benchmark_reports.py REPORT_DIR FRAMEWORK SOURCE_REVISION SOURCE_TREE")
        directory, framework, revision, tree = sys.argv[1:]
        combined, manifest = collect_reports(directory, framework, revision, tree)
        outputs = {Path(directory) / f"combined-report-{framework}.json": combined,
                   Path(directory) / f"current-evidence-{framework}.json": manifest}
        if any(path.exists() for path in outputs):
            raise ValueError("Refusing to replace existing current evidence")
        for path, data in outputs.items():
            with path.open("xb") as stream:
                stream.write(encode(data))
        print(f"Retained 32 current job identities for {framework}; historical acceptance remains unverified")
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as error:
        sys.exit(f"Current benchmark evidence collection failed: {error}")
