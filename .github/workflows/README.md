# GitHub Actions Workflows

This directory contains the automated CI/CD workflows for HeroSD-JWT. The workflows are designed for security, efficiency, and ease of use.

## Workflow Overview

### 1. CI Workflow (`ci.yml`)

**Trigger**: Push to main/develop/claude branches, Pull Requests, Merge Queue

**Purpose**: Continuous integration - builds, tests, and validates code quality

**Jobs**:
- `build-and-test`: Multi-platform (Linux, Windows, macOS) and multi-framework (.NET 8.0, 9.0, 10.0) testing
- `code-quality`: Code formatting checks and build warnings validation
- `pack`: Creates NuGet package artifacts (only on main branch)

**Key Features**:
- Dependency caching for faster builds
- Matrix testing across 3 OS x 3 .NET versions = 9 configurations
- Test result publishing with detailed reports
- Code coverage reporting to Codecov
- Code formatting validation
- Warning-as-error enforcement

**When to use**:
- Runs automatically on every push and PR
- Validates all code before merging

---

### 2. Create Release Workflow (`create-release.yml`)

**Trigger**: Manual dispatch (workflow_dispatch)

**Purpose**: Creates GitHub releases with NuGet packages

**Jobs**:
- `create-release`: Builds, tests, packs NuGet packages, and creates GitHub release with git tag

**Key Features**:
- Version format validation (X.Y.Z or X.Y.Z-prerelease)
- Extracts release notes from CHANGELOG.md
- Creates git tag automatically (v + version)
- Attaches NuGet packages (.nupkg and .snupkg) to release
- Triggers publish-nuget and generate-sboms workflows
- Fast path (~5-10 minutes) - doesn't wait for SBOMs

**How to create a release**:

1. Update CHANGELOG.md with release notes under `## [X.Y.Z] - YYYY-MM-DD`
2. Commit and push changes
3. Go to **Actions** → **Create Release**
4. Click **Run workflow**
5. Enter version (e.g., `1.1.0`)
6. Workflow will:
   - Validate version format
   - Build and test all frameworks
   - Pack NuGet packages
   - Create GitHub release with tag vX.Y.Z
   - Trigger NuGet publish
   - Trigger SBOM generation (async)

**Note**: Version is NOT stored in .csproj - it's passed as a parameter during pack.

---

### 3. Generate SBOMs Workflow (`generate-sboms.yml`)

**Trigger**: Release published event, Manual dispatch

**Purpose**: Generates Software Bill of Materials (SBOM) for supply chain security

**Jobs**:
- `generate-sbom`: Matrix job generating 6 SBOMs in parallel (3 frameworks x 2 SPDX versions)
- `sbom-summary`: Aggregates results and creates summary

**Key Features**:
- Per-framework SBOMs (net8.0, net9.0, net10.0) for accurate dependency tracking
- Dual SPDX format support (2.2 and 3.0)
- Parallel generation for performance
- Attaches SBOMs to existing GitHub release
- fail-fast: false - continues generating other SBOMs if one fails
- Runs asynchronously - doesn't block release or NuGet publish

**SBOM Files Generated**:
- HeroSD-JWT.{version}.net8.0.spdx-2.2.json
- HeroSD-JWT.{version}.net8.0.spdx-3.0.json
- HeroSD-JWT.{version}.net9.0.spdx-2.2.json
- HeroSD-JWT.{version}.net9.0.spdx-3.0.json
- HeroSD-JWT.{version}.net10.0.spdx-2.2.json
- HeroSD-JWT.{version}.net10.0.spdx-3.0.json

**Timeline**: ~15-20 minutes (runs in parallel with NuGet publish)

---

### 4. Publish Workflow (`publish-nuget.yml`)

**Trigger**: create-release workflow completion (workflow_run), Manual dispatch

**Purpose**: Publishes packages to NuGet.org using Trusted Publishing (OIDC)

**Jobs**:
- `publish`: Downloads packages from GitHub release and publishes to NuGet.org

**Key Features**:
- Trusted Publishing with OIDC (no API keys needed)
- Version detection from latest GitHub release
- Downloads pre-built packages from release (no rebuild)
- Package content validation
- Package provenance attestation
- Automatic trigger when create-release completes successfully

**Security**:
- Uses GitHub OIDC tokens (no long-lived API keys)
- Requires `production` environment with manual approval
- Generates cryptographic attestations for supply chain security
- Only runs from the production environment with protection rules

**Manual publish**:
1. Go to **Actions** → **Publish to NuGet**
2. Click **Run workflow**
3. Enter version (e.g., `1.1.0`)
4. Approve in production environment (if required)

---

### 5. Security Scanning Workflow (`scan-security.yml`)

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

## Workflow Dependencies

```
Developer Workflow
        |
        v
Push code / Create PR
        |
        +------------------+
        |                  |
        v                  v
CI Workflow      Security Workflow
- Build           - CodeQL
- Test            - Dep Review
- Quality         - Audit
        |
        v
Merge to main
        |
        v
Update CHANGELOG.md
        |
        v
Trigger: Create Release Workflow (manual)
        |
        v
Create Release Workflow (~5-10 min)
- Build & Test
- Pack NuGet packages
- Create GitHub release with tag
        |
        +------------------+
        |                  |
        v                  v
Publish Workflow   Generate SBOMs Workflow
(~3-4 min)         (~15-20 min, async)
- Download pkgs    - Generate 6 SBOMs
- Publish NuGet    - Attach to release
```

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
   - Automatic in `setup-dotnet@v5`

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

2. **Update CHANGELOG.md before releases**:
   - Add section `## [X.Y.Z] - YYYY-MM-DD`
   - Document all changes under Added, Changed, Fixed, Security sections

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
- Use format: `X.Y.Z` (e.g., `1.1.0`)
- For pre-release: `X.Y.Z-alpha.1`
- Do NOT include 'v' prefix in workflow input

**Problem**: No CHANGELOG entry found
- Add section to CHANGELOG.md: `## [X.Y.Z] - YYYY-MM-DD`
- Commit and push before triggering workflow

**Problem**: Build or test fails
- Fix the issue
- Re-run workflow (it will create/update the same release)

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

### SBOM Generation Failures

**Problem**: SBOM generation fails for specific framework
- Check workflow logs for specific error
- Manually trigger: Actions → Generate SBOMs → Run workflow → Enter version
- Individual SBOM failures don't block release or NuGet publish

**Problem**: SBOMs not attached to release
- Verify release immutability is NOT enabled in repository settings
- Manually trigger generate-sboms workflow

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
5. **Async SBOM generation**: Doesn't block release or NuGet publish
6. **Pre-built packages**: publish-nuget downloads from release instead of rebuilding

**Average workflow times**:
- CI: ~3-5 minutes (with cache)
- Create Release: ~5-10 minutes
- Publish: ~3-4 minutes
- Generate SBOMs: ~15-20 minutes (async, parallel)
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
