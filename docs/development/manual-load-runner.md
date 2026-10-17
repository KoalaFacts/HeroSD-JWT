# Manual BCL load runner

The five existing skipped `SdJwtLoadTests` now use a repository-owned, test-only BCL runner under this repository's MIT license. There is no replacement NuGet dependency, license activation, network service, or subscription. NBomber and the test project's MessagePack security pin are removed. Authentic NuGet restore removed 41 dependencies per net9/net10 test target and 44 on net8; 43 package/version pairs disappear from the whole solution. Shared dependencies remain where still required (for example, BenchmarkDotNet still uses CommandLineParser).

The current resolved test package licenses are recorded in [load-test-license-inventory.json](load-test-license-inventory.json), using the downloaded nuspec metadata and lock-file content hashes. Existing third-party packages retain their own licenses; the runner's MIT license does not replace them.

## Preserved manual workloads

All five existing `Fact(Skip = "Load test - run manually when needed")` settings remain. Remove only the selected test's `Skip` locally and run it in Release, for example:

```sh
dotnet test tests/HeroSdJwt.Tests -c Release --filter FullyQualifiedName~SdJwtLoadTests.VerificationLoadTest
```

| Workload | Arrivals and duration | Existing assertions |
| --- | --- | --- |
| Issuance | 100/s, 10 seconds, 1,000 attempts | Successful RPS > 50; successful P99 < 100 ms |
| Verification | 200/s, 10 seconds, 2,000 attempts; 1,000 pregenerated presentations | Successful RPS > 100; successful P99 < 50 ms; zero failures |
| Key binding | 50/s, 10 seconds, 500 attempts; ten reusable P-256 keys | Successful RPS > 25; successful P99 < 200 ms |
| Mixed | Simultaneous issuance 50/s and verification 100/s, 10 seconds | Issuance successful RPS > 30; verification successful RPS > 40 |
| Stress | Four successive 10-second ramps: 0→10→50→100→200/s | Successful P99 < 500 ms; failure rate < 1% |

Claims, signing algorithms, disclosure selections and cryptographic operations are preserved. The key-binding workload still exports a public key, issues an HS256 credential with that public key, creates a presentation and verifies it. It does not add holder-signature operations. Export stays inside the timed operation, with synchronization around each shared ECDsa instance. Keys are disposed in `finally`, including partial setup or cancellation.

Mixed workload storage starts empty. Each successful issuance inserts one presentation and each verification consumes at most one. Missing presentations remain failed requests; there is no prefill, retry or reuse. Retained payloads are bounded by the finite issuance budget (500 for the manual profile).

## Explicit timing conventions

The runner is open-model: absolute `Stopwatch` arrival times are independent of operation completion. Setup is outside measurement and there is no warm-up. Each interval's arrivals are deterministically spaced at its subinterval midpoints instead of random jitter. For ramp interval k, the count is `Round(start + (target - start) * k / numberOfIntervals, AwayFromZero)`. A subsequent stage inherits the previous target. The initial zero-arrival interval still consumes time, and no extra endpoint bucket is added. The stress profile therefore offers 45 + 280 + 725 + 1,450 = 2,500 operations over 40 seconds.

These are documented replacement conventions, not a claim of identical internal NBomber 6.1.2 scheduling. The [official simulation documentation](https://nbomber.com/docs/nbomber/load-simulation/#ramping-inject) defines linear, inherited open-model ramps. Historical [scheduler](https://github.com/PragmaticFlow/NBomber/blob/v6.1.2/src/NBomber/Domain/Scheduler/ScenarioScheduler.fs) and [actor](https://github.com/PragmaticFlow/NBomber/blob/v6.1.2/src/NBomber/Domain/Concurrency/ScenarioActor.fs) sources inform the conventions, but that public tag contains stale project metadata and is not sufficient proof of the released package's internals. No NBomber runtime is invoked by this replacement.

Successful RPS is successful completions divided by elapsed wall time, including the full scheduled duration and worker drain. P99 is exact nearest-rank over successful requests only. Latency starts at the intended arrival, so scheduler delay and queue waiting are included instead of hidden. This is deliberately stricter than timing only the operation body; historical NBomber latency measurements are not directly interchangeable. Failure rate includes false results, exceptions and capacity-rejected arrivals. Zero-success runs have infinite P99, and an entirely empty run has a failure rate of one.

## Bounds and cleanup

- Default: 64 fixed workers and 256 queue slots per scenario. Limits: 256 workers, 4,096 queue slots, 16 scenarios.
- Each schedule is capped at 1,000,000 requests and 60,000 interval buckets; each stage is at most one hour. Exact latency storage is at most 8 MB per scenario. The manual scenarios are much smaller.
- A full queue immediately counts an arrival as failed/rejected. It never slows the scheduler to disguise overload. Every manual test additionally asserts zero capacity rejections and at least one success.
- Operation exceptions are failures; at most five diagnostic messages of at most 512 characters are retained. Result payloads and task-per-request lists are not retained.
- Cancellation propagates to operations, closes the queue and awaits all worker tasks before returning. Cancellation is cooperative: synchronous crypto cannot be forcibly stopped mid-call, and an operation that ignores cancellation must finish before resources are released.
- Results are printed through xUnit output. There is no HTML dashboard or NBomber report compatibility layer.

## Verification boundary

Deterministic tests cover counts, inherited ramps, interval spacing, nearest-rank P99, successful throughput, failure accounting and invalid/bounded inputs. Short asynchronous tests cover concurrency, capacity rejection, operation exceptions, cancellation and draining. `LoadWorkloadSmokeTests` executes all five real workload implementations with four issued operations per profile and eight mixed verification attempts, taking roughly half a second of scheduled time. Mixed smoke verification may legitimately report zero successes on a delayed host; a separate deterministic empty→issue→consume→empty check verifies both successful consumption and empty-read failures using the same operation delegates. This is a functional proof, not a high-load performance result.

The full 10–40-second manual profiles remain opt-in. BenchmarkDotNet, its historical measurements and the 105% CI regression gate are unchanged. Previously observed performance alerts remain unresolved; removing NBomber does not clear them, reset a baseline or authorize green-seeking reruns.
