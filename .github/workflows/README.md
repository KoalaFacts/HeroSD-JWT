# GitHub Actions Workflows

This directory contains the automated CI/CD workflows for HeroSD-JWT. The workflows are designed for security, efficiency, and ease of use.

## Workflow Overview

### 1. CI Workflow (`ci.yml`)

**Trigger**: Push to main/develop/claude branches, Pull Requests, Merge Queue

**Purpose**: Continuous integration - builds, tests, and validates code quality

**Jobs**:
- `build-and-test`: Multi-platform (Linux, Windows, macOS) and multi-version (.NET 8 & 9) testing
- `code-quality`: Code formatting checks and build warnings validation
- `pack`: Creates NuGet package artifacts (only on main branch)

**Key Features**:
- ✅ Dependency caching for faster builds
- ✅ Matrix testing across 3 OS × 2 .NET versions = 6 configurations
- ✅ Test result publishing with detailed reports
- ✅ Code coverage reporting to Codecov
- ✅ Code formatting validation
- ✅ Warning-as-error enforcement

**When to use**:
- Runs automatically on every push and PR
- Validates all code before merging

---

### 2. Release Workflow (`release.yml`)

**Trigger**: Tag push (v*), Manual dispatch

**Purpose**: Creates GitHub releases with automated changelog generation

**Jobs**:
- `create-release`: Builds packages, generates changelog, creates/updates GitHub release

**Key Features**:
- ✅ Automated changelog generation from git commits
- ✅ Groups changes by type (Features, Fixes, Docs, etc.)
- ✅ Attaches NuGet packages (.nupkg and .snupkg) to release
- ✅ Validates tag format (vX.Y.Z or vX.Y.Z-prerelease)
- ✅ Supports updating existing releases
- ✅ Marks pre-release versions automatically

**Changelog Format**:
Commits are automatically categorized by prefix:
- `feat:` / `feature:` → Features section
- `fix:` → Bug Fixes section
- `docs:` → Documentation section
- `test:` → Tests section
- `chore:` → Chores & Maintenance section

**How to create a release**:

```bash
# 1. Update version in src/HeroSdJwt.csproj
# 2. Commit your changes
git add src/HeroSdJwt.csproj
git commit -m "chore: bump version to 1.2.0"

# 3. Create and push tag
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0

# 4. GitHub Actions will automatically create the release with changelog
```

Or manually trigger:
1. Go to **Actions** → **Create Release**
2. Click **Run workflow**
3. Enter tag (e.g., `v1.2.0`)

---

### 3. Publish Workflow (`publish-nuget.yml`)

**Trigger**: GitHub release published, Manual dispatch

**Purpose**: Publishes packages to NuGet.org using Trusted Publishing (OIDC)

**Jobs**:
- `publish`: Builds, tests, packs, validates, and publishes to NuGet.org

**Key Features**:
- ✅ **Trusted Publishing** with OIDC (no API keys!)
- ✅ Version format validation
- ✅ Full test suite execution before publishing
- ✅ Package content validation
- ✅ Package provenance attestation
- ✅ Symbols package (.snupkg) generation
- ✅ Dependency caching
- ✅ Detailed release summary

**Security**:
- Uses GitHub OIDC tokens (no long-lived API keys)
- Requires `production` environment with manual approval
- Generates cryptographic attestations for supply chain security
- Only runs from the production environment with protection rules

**Manual publish**:
1. Go to **Actions** → **Publish to NuGet**
2. Click **Run workflow**
3. Enter version (e.g., `1.2.0`)
4. Approve in production environment (if required)

---

### 4. Security Scanning Workflow (`security.yml`)

**Trigger**: Push to main/develop, PRs, Weekly schedule (Monday 00:00 UTC), Manual

**Purpose**: Automated security scanning and vulnerability detection

**Jobs**:
- `codeql-analysis`: Static code analysis for security vulnerabilities
- `dependency-review`: Reviews dependency changes in PRs (blocks unsafe dependencies)
- `nuget-audit`: Scans NuGet packages for known vulnerabilities
- `secret-scanning`: Detects accidentally committed secrets
- `security-summary`: Aggregates security scan results

**Key Features**:
- ✅ CodeQL static analysis (security-extended queries)
- ✅ Dependency vulnerability scanning
- ✅ License compliance checking (blocks GPL, AGPL)
- ✅ Secret detection with TruffleHog
- ✅ Weekly scheduled scans
- ✅ Automatic PR comments with findings

**What gets scanned**:
- Source code for security vulnerabilities (SQL injection, XSS, etc.)
- NuGet dependencies for CVEs
- License compliance (rejects GPL, AGPL)
- Secrets in code (API keys, tokens, passwords)

---

## Workflow Dependencies

```
┌─────────────────────────────────────────────────────────┐
│                    Developer Workflow                    │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌──────────────────────────────────────┐
        │  Push code / Create PR               │
        └──────────────────────────────────────┘
                            │
        ┌───────────────────┴────────────────────┐
        │                                         │
        ▼                                         ▼
┌───────────────┐                      ┌──────────────────┐
│  CI Workflow  │                      │Security Workflow │
│               │                      │                  │
│ • Build       │                      │ • CodeQL         │
│ • Test        │                      │ • Dep Review     │
│ • Quality     │                      │ • Audit          │
└───────────────┘                      └──────────────────┘
        │
        ▼
┌──────────────────────┐
│  Merge to main       │
└──────────────────────┘
        │
        ▼
┌──────────────────────┐
│  Create tag (vX.Y.Z) │
└──────────────────────┘
        │
        ▼
┌──────────────────────┐
│ Release Workflow     │
│                      │
│ • Build packages     │
│ • Generate changelog │
│ • Create release     │
└──────────────────────┘
        │
        ▼
┌──────────────────────┐
│ Publish Workflow     │
│                      │
│ • Validate           │
│ • Test               │
│ • Publish to NuGet   │
└──────────────────────┘
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
| `production` | NuGet package publishing | ✅ Required reviewers<br>✅ Deployment branches: main only |

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
   - Automatic in `setup-dotnet@v4`

**Cache hits save ~30-60 seconds per workflow run.**

---

## Best Practices

### For Contributors

1. **Write good commit messages** with conventional prefixes:
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

3. **Keep PRs focused**: One feature/fix per PR for cleaner changelogs

### For Maintainers

1. **Use semantic versioning**:
   - `vX.Y.Z` for stable releases
   - `vX.Y.Z-alpha.1` for pre-releases

2. **Review security scan results weekly**

3. **Approve production deployments** carefully

4. **Keep dependencies updated**:
   ```bash
   dotnet list package --outdated
   ```

---

## Troubleshooting

### CI Failures

**Problem**: Tests fail on specific OS/version
- Check test logs in Actions → CI → specific job
- Run locally: `dotnet test --framework net8.0` or `net9.0`

**Problem**: Code formatting fails
- Run: `dotnet format`
- Commit formatting changes

### Release Failures

**Problem**: Tag format invalid
- Use format: `vX.Y.Z` (e.g., `v1.2.0`)
- For pre-release: `vX.Y.Z-alpha.1`

**Problem**: Release already exists
- Workflow will update existing release with new assets
- Or delete the release and re-run

### Publish Failures

**Problem**: Authentication fails
- Verify `NUGET_USERNAME` secret is set correctly
- Check Trusted Publishing policy on NuGet.org
- Ensure `production` environment exists

**Problem**: Version already exists
- NuGet doesn't allow overwriting versions
- Bump version and create new tag

**Problem**: Tests fail during publish
- Check test logs
- Fix tests and create new tag

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

1. **Parallel matrix builds**: 6 configurations run simultaneously
2. **Dependency caching**: ~45 second savings per run
3. **Conditional jobs**: Jobs only run when needed
4. **Artifact retention**: 7-30 days based on importance
5. **Fail-fast disabled**: See all failures, not just first

**Average workflow times**:
- CI: ~3-5 minutes (with cache)
- Release: ~2-3 minutes
- Publish: ~3-4 minutes
- Security: ~8-12 minutes

---

## Maintenance

### Monthly Tasks

- [ ] Review security scan results
- [ ] Update action versions (Dependabot PRs)
- [ ] Check for outdated NuGet packages
- [ ] Review workflow run metrics

### Quarterly Tasks

- [ ] Review and optimize caching strategy
- [ ] Audit GitHub environments and secrets
- [ ] Review Trusted Publishing policies
- [ ] Update this documentation

---

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [NuGet Trusted Publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package#trusted-publishing)
- [CodeQL for C#](https://codeql.github.com/docs/codeql-language-guides/codeql-for-csharp/)
- [Semantic Versioning](https://semver.org/)
- [Publishing Guide](../../PUBLISHING.md)

---

## Questions or Issues?

- **Workflow issues**: Check [Actions](../../actions) logs
- **Security concerns**: Check [Security](../../security) tab
- **Questions**: Open a [Discussion](../../discussions)
- **Bugs**: Open an [Issue](../../issues)
