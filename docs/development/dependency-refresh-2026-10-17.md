# Dependency refresh, 2026-10-17

This compatible-version refresh builds on the secure SDK and locked-restore repair in PR #68.
It retains `net8.0;net9.0;net10.0`, the pinned 8.0.426 / 9.0.319 / 10.0.402 SDKs, locked restore, package auditing, warnings-as-errors, and security defaults. No production C# or public API changes are part of this batch.

## NuGet packages

Versions were checked against the official NuGet flat-container indexes. Framework-specific Microsoft packages stay on their matching major.

| Package | Previous direct version(s) | Selected version(s) |
| --- | --- | --- |
| [BenchmarkDotNet](https://www.nuget.org/packages/BenchmarkDotNet) | 0.15.7 | 0.15.8 |
| [Microsoft.OpenApi](https://www.nuget.org/packages/Microsoft.OpenApi) | 2.7.5 | 2.12.2 |
| [Swashbuckle.AspNetCore](https://www.nuget.org/packages/Swashbuckle.AspNetCore) | 10.0.1 | 10.3.0 |
| [Microsoft.AspNetCore.OpenApi](https://www.nuget.org/packages/Microsoft.AspNetCore.OpenApi) | 10.0.0, 9.0.10 | 10.0.13, 9.0.21 |
| [Scalar.AspNetCore](https://www.nuget.org/packages/Scalar.AspNetCore) | 2.10.3 | 2.18.0 |
| [Microsoft.Bcl.Memory](https://www.nuget.org/packages/Microsoft.Bcl.Memory) | 10.0.8 | 10.0.13 |
| [coverlet.collector](https://www.nuget.org/packages/coverlet.collector) | 6.0.4 | 6.0.4 |
| [Microsoft.NET.Test.Sdk](https://www.nuget.org/packages/Microsoft.NET.Test.Sdk) | 18.0.1 | 18.11.0 |
| [xunit.v3](https://www.nuget.org/packages/xunit.v3) | 3.2.0 | 3.2.2 |
| [xunit.runner.visualstudio](https://www.nuget.org/packages/xunit.runner.visualstudio) | 3.1.5 | 3.1.5 |
| [Microsoft.AspNetCore.TestHost](https://www.nuget.org/packages/Microsoft.AspNetCore.TestHost) | 10.0.0, 8.0.11, 9.0.0 | 10.0.13, 8.0.32, 9.0.21 |
| [Bogus](https://www.nuget.org/packages/Bogus) | 35.6.5 | 35.6.5 |
| [CsCheck](https://www.nuget.org/packages/CsCheck) | 4.4.1 | 4.9.1 |
| [NBomber](https://www.nuget.org/packages/NBomber) | 6.1.2 | 6.1.2 (license review deferred) |
| [MessagePack](https://www.nuget.org/packages/MessagePack) | 2.5.307 | 2.5.307 |
| [Microsoft.Extensions.Caching.Memory](https://www.nuget.org/packages/Microsoft.Extensions.Caching.Memory) | 9.0.0 | 9.0.21 |

The .NET 9 examples retain Microsoft.OpenApi 1.x through Microsoft.AspNetCore.OpenApi 9.0.21. The .NET 8 and .NET 10 examples explicitly use OpenApi 2.12.2, which satisfies the ASP.NET Core 10.0.13 dependency range `[2.12.2, 3.0.0)`. NBomber remains at 6.1.2; the explicit MessagePack 2.5.307 pin protects its older transitive dependency.

## GitHub Actions

Every external action remains pinned to the full commit SHA verified from its official release tag. No workflow permissions, publication triggers, SDK targets, or benchmark thresholds change.

| Action | Selected release | Commit |
| --- | --- | --- |
| [actions/checkout](https://github.com/actions/checkout/releases/tag/v7.0.1) | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| [actions/upload-artifact](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| [actions/download-artifact](https://github.com/actions/download-artifact/releases/tag/v8.0.2) | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| [codecov/codecov-action](https://github.com/codecov/codecov-action/releases/tag/v7.1.1) | v7.1.1 | `303a32d7a59b442fa8d48b6a1cc6825c09c847a5` |
| [actions/dependency-review-action](https://github.com/actions/dependency-review-action/releases/tag/v5.0.0) | v5.0.0 | `a1d282b36b6f3519aa1f3fc636f609c47dddb294` |
| [actions/attest-build-provenance](https://github.com/actions/attest-build-provenance/releases/tag/v4.2.2) | v4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` |
| [NuGet/login](https://github.com/NuGet/login/releases/tag/v1.2.0) | v1.2.0 | `8d196754b4036150537f80ac539e15c2f1028841` |
| [benchmark-action/github-action-benchmark](https://github.com/benchmark-action/github-action-benchmark/releases/tag/v1.22.2) | v1.22.2 | `4322e5726e6334590d251fc4f92bec0efafc45dc` |
| [actions/setup-dotnet](https://github.com/actions/setup-dotnet/releases/tag/v6.0.0) | v6.0.0 | `a98b56852c35b8e3190ac28c8c2271da59106c68` |
| [microsoft/security-devops-action](https://github.com/microsoft/security-devops-action/releases/tag/v1.12.0) | v1.12.0 | `08976cb623803b1b36d7112d4ff9f59eae704de0` |
| [github/codeql-action](https://github.com/github/codeql-action/releases/tag/v4.39.0) | v4.39.0 | `6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee` |

setup-dotnet v6 uses the same inputs, outputs, and Node 24 runtime as v5.4; its documented ESM migration does not change the wrapper contract.

## Deliberately separate migrations

- NBomber 6.7.1: its bundled license changes from v2.0 to [v3.2](https://nbomber.com/assets/NBOMBER-LICENSE-AGREEMENT-3.2.pdf), which explicitly requires a commercial subscription for organizational use. Retain 6.1.2 until project applicability is reviewed; the older version also has a proprietary subscription agreement, so retention does not establish a free organizational-use entitlement. A temporary validation probe ran the newer package before this distinction was noticed, but it is excluded from this dependency commit.

- xunit.v3 4.x and xunit.runner.visualstudio 4.x: keep the existing xUnit 3/VSTest integration while refreshing its 3.x patch. A test-platform migration deserves a separate suite/coverage verification.
- coverlet.collector 10.x: keep the existing 6.0.4 coverage collector, its latest 6.x release. Changing coverage infrastructure is separate from this compatible batch.
- Microsoft.OpenApi 3.x: incompatible with the ASP.NET Core 10 package's upper bound and the .NET 9 1.x integration.
- MessagePack 3.x: do not force a serialization-major change under NBomber's 2.x contract.
- Microsoft.Extensions.Caching.Memory 10.x: the test-only reference stays on its patched 9.0.21 line for this batch.

## Performance evidence

The previous PR head's net8 benchmark alert remains recorded in PR #68. Its 105% threshold, framework-isolated historical measurements, configured jobs, and raw history are preserved. A fresh dependency commit receives its normal CI measurement; no green-seeking rerun or baseline reset is part of this update.

## Validation

Validation results are recorded in PR #68 against the exact submitted head. A clean local build alone does not establish NativeAOT compatibility; an independent .NET 11 consumer probe failed on unmodified head 9b90380 before this dependency refresh. The .NET 10 AOT control was blocked by its task-host environment, so the runtime origin of that issue is not established.

Local validation of the final selection: locked restore and the all-framework Release build pass with warnings treated as errors (0 warnings, 0 errors); 3,474 tests pass, with the five existing manual-load skips per framework unchanged. Six nonempty coverage files were produced. Transitive audit reports no vulnerable packages in all seven projects. Both example apps start and serve Scalar on all frameworks; their configured net9/net10 OpenAPI endpoints return HTTP 200 and valid nonempty documents. The seven benchmark-baseline guard tests pass. Full semantic formatting is blocked locally by the environment's Roslyn named-pipe restriction and must be verified by CI.
