# GitHub Actions Workflows

These sections follow the current workflow files. Maintainer release instructions: [publishing guide](../../docs/maintainers/publishing-guide.md).

## Workflow Overview

### 1. CI (`ci.yml`)

Runs on pushes/PRs/merge groups. Tests Windows/Linux/macOS × .NET 8/9/10; Code Quality validates Release build, formatting and package hash regression; Dependency Review inspects dependency changes. Three local NuGet consumer smoke jobs install the **packed core package**, not a project reference, on .NET 8/9/10. These tests do not verify NuGet.org availability.

### 2. Create Release (`create-release.yml`)

**Manual dispatch from current `main`**, with an explicit version such as `2.0.0`. Verifies main SHA and that the tag does not exist; restores/builds/tests, packs/smoke-tests the core .nupkg/.snupkg, records source SHA and both SHA-256 digests in the exact-run identity artifact, generates SBOMs and creates a GitHub Release/tag. It does **not** auto-commit the changelog. Pushing a tag alone is not a release trigger. Dotted prerelease suffixes are not accepted by the current regex.

### 3. Publish to NuGet (`publish-nuget.yml`)

After successful Create Release on main, automatic `workflow_run` publication reads identity from the **exact triggering run**, validates release tag/source SHA and downloaded package SHA-256 digests, then attests and publishes through `production` using NuGet Trusted Publishing/OIDC. Only the core package is published.

The **manual dispatch** emergency path requires an explicit version and does **not** use triggering-run identity/tag/hash verification; verify that evidence independently before using it.

---

### 4. Security Scanning Workflow (`scan-security.yml`)

**Trigger**: Push to main/develop, Weekly schedule (Monday 00:00 UTC), Manual

**Purpose**: Automated security scanning and vulnerability detection

**Jobs**:
- `nuget-audit`: Scans NuGet packages for known vulnerabilities using Microsoft Security DevOps
- `security-summary`: Aggregates security scan results

**Key Features**:
- CodeQL static analysis via GitHub default setup
- NuGet dependency vulnerability scanning
- BinSkim binary analysis
- CredScan secret detection
- Weekly scheduled scans
- Dependency review for PRs (handled in CI workflow)

**What gets scanned**:
- Source code for security vulnerabilities (via GitHub CodeQL default setup)
- NuGet dependencies for CVEs (dotnet list package --vulnerable)
- Binary security (BinSkim)
- Credentials in code (CredScan)

---

### 5. Performance Benchmarks (`perform-benchmarks.yml`)

Each target framework compares only with its own `Benchmark netX.0` history in
`gh-pages:dev/bench/data.js`. Historical validation rejects a missing or empty framework
baseline before comparison or storage; it never falls back to another framework or
silently starts a new baseline. Current evidence collection runs first so an
unrecoverable historical ambiguity does not prevent fresh diagnostic evidence. Keep the 105% alert threshold and failure gate.
Run the preflight regression tests with:

```bash
python3 -m unittest discover -s .github/scripts/tests
```

`collect_benchmark_reports.py` replaces the lossy wildcard `jq` combination. It
requires exactly one full report for each of the three benchmark classes, the
16 expected names and both configured jobs for every name (32 rows total).
Each file must use the pinned BenchmarkDotNet 0.15.8 nanosecond JSON schema,
target the requested .NET framework, and have identical host metadata. Missing,
extra, duplicate or unknown identities, invalid numbers, and mismatched units
fail closed before historical comparison. Raw files and measurement arrays are
not rewritten; the separate `current-evidence-netX.0.json` manifest records every
source filename and SHA-256, each row's source and configured job, the combined
report hash, and the actual checked-out Git revision/tree (which can be a PR merge
revision rather than the PR head). These hashes bind the retained evidence;
they do not independently authenticate an arbitrary externally supplied report.

The ordinary CI matrix and 60-minute job timeout are unchanged. After successful
current collection, historical validation must still pass before comparison or
storage can run. While historical job coverage is unverified, the manifest says
`historical_coverage_unverified` and `historical_acceptance_passed: false`; complete
current evidence is diagnostic, not an acceptance verdict. The always-run artifact
upload retains reports and manifests even when historical validation fails.

The original shared `Benchmark` history is preserved unchanged. Its three entries
were copied into framework-specific histories using the non-overlapping store
step times from [run 26753534673](https://github.com/KoalaFacts/HeroSD-JWT/actions/runs/26753534673):

| Framework | Entry timestamp (milliseconds) | Store step, 2026-06-01 UTC | Job |
| --- | --- | --- | --- |
| net8.0 | 1780315504094 | 12:05:03–12:05:06 | [78847373490](https://github.com/KoalaFacts/HeroSD-JWT/actions/runs/26753534673/job/78847373490) |
| net9.0 | 1780315520781 | 12:05:20–12:05:22 | [78847373527](https://github.com/KoalaFacts/HeroSD-JWT/actions/runs/26753534673/job/78847373527) |
| net10.0 | 1780315501444 | 12:05:01–12:05:03 | [78847373574](https://github.com/KoalaFacts/HeroSD-JWT/actions/runs/26753534673/job/78847373574) |

All entries retain their original commit, timestamps, and 32 measurements,
including the existing custom-job/ShortRun duplicates. No measurement or threshold
was reset. The original raw file remains available at
[`6a260993:dev/bench/data.js`](https://github.com/KoalaFacts/HeroSD-JWT/blob/6a2609931f308092c43a962e792a0e353a8d771f/dev/bench/data.js)
(SHA-256 `de68172aa4e39d645c3c83d95d5de0f1a7005d18f22ff2f671e907033b9976bc`).
Adding a framework requires a separately verified, attributable baseline first.

The comparison also requires one unambiguous identity per configured benchmark
job. BenchmarkDotNet's `FullName` alone omits the job; the third-party action
otherwise compares both the 10-iteration job and 3-iteration ShortRun with the
first historical row of that name. The preflight now rejects duplicate historical
names explicitly. Historical rows are not assigned a job from array order, dropped,
or reset. Until verified job provenance is available, this is an infrastructure
ambiguity failure, not a cleared performance gate.

For future attributable histories, `prepare_benchmark_comparison.py` writes a
separate `comparison-report-netX.0.json`, adding the configured iteration, launch,
and warmup counts to each `FullName`. Random generated job IDs and retained sample
counts are not identities. Original full reports, combined JSON, measurement
arrays, and history remain unchanged. Unknown job configurations, duplicate jobs,
missing/extra identities, unsupported units, and invalid timing values fail closed.

The exact preflight snapshot's 105% gate runs before local result preparation.
The upstream action has `auto-push: false`: it may refetch history and prepare a
local gh-pages commit, but must finish its own alerts before any remote write.
The retained snapshot is also checked afterward, even if preparation fails.

`validate_benchmark_publication.py` resolves the prepared commit once and checks
both the retained snapshot and that commit's actual parent using the same
historical identity and 105% gates. It requires preservation of all history and
other framework suites, exactly one appended result matching the original raw
means/names/units and current commit, and no unrelated changed files. Only after
all steps succeed may a push-to-main run publish that exact validated SHA using
an ordinary non-force push. There is no refetch/rebase/retry after validation.
Competing forward/divergent updates therefore fail closed; this is not a strict
compare-and-swap guarantee against administrative force-rewinds of gh-pages.
Main-push framework jobs are serialized to avoid competing with each other;
PR/dispatch jobs retain parallel measurement and never publish remotely.

All gates read the single `BENCHMARK_ALERT_THRESHOLD` setting. Dispatch metadata
is pinned to the workflow SHA. No new historical acceptance or credentials are
introduced, and existing snapshot and upstream alert checks remain enabled.

Current raw collection requires nonempty `Workload`/`Result` measurements and
an integer `Statistics.N` equal to their count, as defined by the pinned BDN
exporter. These are already adjusted by BDN for overhead and outlier removal;
the retained count need not equal the configured iteration count. This check
does not recompute outliers, reassign jobs, or establish historical acceptance.

Raw BenchmarkDotNet logs and full/combined JSON reports are uploaded directly from
`BenchmarkDotNet.Artifacts` after both successful and failed benchmark comparisons,
independent of the comparison action's outputs. Each framework has its own
`benchmark-results-netX.0` artifact with 30-day retention. Uploads include only root
`.log` files and `results/*.json`; hidden files, generated builds, and other
repository files are excluded. If an earlier failure produced no artifacts, the
upload warns without replacing that original failure. This evidence collection
does not alter the benchmark failure gate, jobs, historical data, or 105% threshold.

---

## Workflow Dependencies

Current main: CI + Security + local NuGet consumer smoke
  → authorized manual **Create Release** from main
  → exact source SHA / core package SHA-256 identity, GitHub Release and tag
  → successful automatic **Publish to NuGet**
  → tag/hash verification, attestation, production environment, NuGet.org

Manual emergency Publish to NuGet deliberately lacks the automatic exact-run provenance check. See the [publishing guide](../../docs/maintainers/publishing-guide.md).

---

## Environment Setup

### Required Secrets

| Secret | Purpose | Where to Add |
|--------|---------|--------------|
| `NUGET_USERNAME` | Your NuGet.org username for Trusted Publishing | Repository Secrets |

### Required Environments

| Environment | Purpose | Protection Rules |
|-------------|---------|------------------|
| `production` | NuGet package publishing | Required reviewers, Deployment branches: main only |

### Setting up Trusted Publishing

1. **Configure NuGet.org**:
   - Go to https://www.nuget.org/ → Your account → Trusted Publishing
   - Create policy:
     - Repository: `KoalaFacts/HeroSD-JWT`
     - Workflow: `publish-nuget.yml`
     - Environment: `production`

2. **Configure GitHub**:
   - Settings → Secrets → Actions → New secret
     - Name: `NUGET_USERNAME`
     - Value: Your NuGet.org username
   - Settings → Environments → New environment
     - Name: `production`
     - Add protection rules (reviewers, branch restrictions)

See [PUBLISHING.md](../../PUBLISHING.md) for detailed setup instructions.

---

## Caching Strategy

All workflows use multi-layer caching:

1. **NuGet package cache** (`~/.nuget/packages`)
   - Key: `{os}-nuget-{csproj hash}`
   - Speeds up dependency restoration

2. **.NET SDK cache** (via `setup-dotnet` action)
   - Caches .NET SDK downloads
   - Automatic in `setup-dotnet@v6`

**Cache hits save approximately 30-60 seconds per workflow run.**

---

## Best Practices

### For Contributors

1. **Follow conventional commit format** (for consistency):
   ```
   feat: add new feature
   fix: resolve bug in verification
   docs: update README
   test: add unit tests for encoder
   chore: update dependencies
   ```

2. **Always run locally before pushing**:
   ```bash
   dotnet restore
   dotnet build --configuration Release
   dotnet test --configuration Release
   dotnet format --verify-no-changes
   ```

3. **Keep PRs focused**: One feature/fix per PR for easier review

### For Maintainers

1. **Use semantic versioning**:
   - `X.Y.Z` for stable releases
   - `X.Y.Z-alpha.1` for pre-releases

2. **Release process starts with authorized manual dispatch**:
   - Verify current main plus its checked checks and changelog/upgrade guide
   - Run Create Release from main with a supported version
   - GitHub release notes are generated, but CHANGELOG.md is not committed automatically

3. **Review security scan results weekly**

4. **Approve production deployments carefully**

5. **Keep dependencies updated**:
   ```bash
   dotnet list package --outdated
   ```

---

## Troubleshooting

### CI Failures

**Problem**: Tests fail on specific OS/framework
- Check test logs in Actions → CI → specific job
- Run locally: `dotnet test --framework net8.0` or `net9.0` or `net10.0`

**Problem**: Code formatting fails
- Run: `dotnet format`
- Commit formatting changes

### Release Failures

**Problem**: Version format invalid
- Use `X.Y.Z` (e.g. `2.0.0`)
- Only one alphanumeric prerelease suffix is supported (e.g. `2.0.0-rc`), not `rc.1`
- Do NOT include 'v' prefix in workflow input

**Problem**: Build or test fails
- Fix through an ordinary PR and verify the new main
- Re-dispatch only after checking whether the GitHub Release/tag already exists

**Problem**: Main moved during Create Release
- Recheck the remote main SHA and its current checks
- Dispatch a fresh Create Release from main; the workflow does not auto-commit CHANGELOG.md

### Publish Failures

**Problem**: Authentication fails
- Verify `NUGET_USERNAME` secret is set correctly
- Check Trusted Publishing policy on NuGet.org
- Ensure `production` environment exists

**Problem**: Version already exists on NuGet.org
- NuGet doesn't allow overwriting versions
- Bump version and create new release

**Problem**: Cannot download packages from release
- Ensure create-release workflow completed successfully
- Check that release v{version} exists with .nupkg and .snupkg assets

**Problem**: SBOM generation fails
- Check workflow logs for specific framework error
- SBOMs are generated inline, failure will stop the release
- Fix the issue and re-run the workflow

### Security Scan Failures

**Problem**: CodeQL finds vulnerabilities
- Review the security alert in GitHub Security tab
- Fix the vulnerability
- Re-run scan

**Problem**: Vulnerable dependencies detected
- Run: `dotnet list package --vulnerable`
- Update vulnerable packages
- If no update available, consider alternatives

---

## Performance Optimizations

Current optimizations:

1. **Parallel matrix builds**: 9 configurations run simultaneously in CI
2. **Dependency caching**: Approximately 45 second savings per run
3. **Conditional jobs**: Jobs only run when needed
4. **Artifact retention**: 1-90 days based on importance
5. **Inline SBOM generation**: Fast sequential generation (~30 seconds total)
6. **Pre-built packages**: publish-nuget downloads from release instead of rebuilding
7. **Automated CHANGELOG**: No manual editing, auto-committed with [skip ci]

**Average workflow times**:
- CI: ~3-5 minutes (with cache)
- Create Release: ~5-10 minutes (includes SBOM generation)
- Publish: ~3-4 minutes
- Security: ~8-12 minutes

---

## Maintenance

### Monthly Tasks

- Review security scan results
- Update action versions (Dependabot PRs)
- Check for outdated NuGet packages
- Review workflow run metrics

### Quarterly Tasks

- Review and optimize caching strategy
- Audit GitHub environments and secrets
- Review Trusted Publishing policies
- Update this documentation

---

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [NuGet Trusted Publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package#trusted-publishing)
- [CodeQL for C#](https://codeql.github.com/docs/codeql-language-guides/codeql-for-csharp/)
- [Semantic Versioning](https://semver.org/)
- [SPDX Specification](https://spdx.dev/specifications/)
- [Microsoft SBOM Tool](https://github.com/microsoft/sbom-tool)
- [Publishing Guide](../../PUBLISHING.md)

---

## Questions or Issues?

- **Workflow issues**: Check [Actions](../../actions) logs
- **Security concerns**: Check [Security](../../security) tab
- **Questions**: Open a [Discussion](../../discussions)
- **Bugs**: Open an [Issue](../../issues)
