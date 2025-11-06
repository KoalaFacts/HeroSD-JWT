# Publishing Guide for HeroSD-JWT

**Purpose:** Complete guide for publishing NuGet packages and managing releases
**Audience:** Package maintainers
**Last Updated:** 2025-11-06

---

## Table of Contents

- [Quick Start](#quick-start)
- [Versioning Strategy](#versioning-strategy)
- [Publishing Setup](#publishing-setup)
- [Publishing Methods](#publishing-methods)
- [Pre-Release Checklist](#pre-release-checklist)
- [Post-Publishing Verification](#post-publishing-verification)
- [Changelog Management](#changelog-management)
- [Git Tagging Strategy](#git-tagging-strategy)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

---

## Quick Start

For maintainers who need to publish immediately:

```bash
# 1. Update version in .csproj
# Edit src/HeroSdJwt/HeroSdJwt.csproj → <Version>1.0.8</Version>

# 2. Update CHANGELOG.md
# Add entry for new version

# 3. Commit changes
git add src/HeroSdJwt/HeroSdJwt.csproj CHANGELOG.md
git commit -m "chore: bump version to 1.0.8"
git push origin main

# 4. Create and push tag
git tag -a v1.0.8 -m "Release v1.0.8"
git push origin v1.0.8

# 5. GitHub Actions automatically publishes to NuGet
# (requires approval if production environment has reviewers)

# 6. Verify on NuGet.org
# https://www.nuget.org/packages/HeroSD-JWT/1.0.8
```

**Continue reading for detailed instructions...**

---

## Versioning Strategy

### Semantic Versioning (SemVer)

Follow [Semantic Versioning 2.0.0](https://semver.org/):

**Format**: `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`

- **MAJOR** (1.x.x): Breaking changes, incompatible API changes
- **MINOR** (x.1.x): New features, backwards-compatible
- **PATCH** (x.x.1): Bug fixes, backwards-compatible
- **PRERELEASE** (x.x.x-alpha.1): Pre-release versions
- **BUILD** (x.x.x+build.123): Build metadata (not used for NuGet)

### Version Bumping Rules

| Change Type | Version Bump | Example |
|-------------|--------------|---------|
| Bug fix (no API changes) | PATCH | 1.0.0 → 1.0.1 |
| New feature (backwards compatible) | MINOR | 1.0.1 → 1.1.0 |
| Breaking change or major rewrite | MAJOR | 1.1.0 → 2.0.0 |
| Pre-release for next version | PRERELEASE | 2.0.0-alpha.1 |

### When to Increment

**MAJOR version when:**
- Remove public APIs
- Change method signatures
- Change behavior that breaks existing consumers
- Major architectural changes

**MINOR version when:**
- Add new public APIs
- Add optional parameters with defaults
- Add new features without breaking existing code
- Deprecate APIs (but don't remove them)

**PATCH version when:**
- Fix bugs
- Performance improvements
- Documentation updates
- Internal refactoring (no API changes)

### Version Decision Tree

```
Breaking change? → MAJOR (2.0.0)
    ↓ No
New feature? → MINOR (1.1.0)
    ↓ No
Bug fix? → PATCH (1.0.1)
```

---

## Publishing Setup

### Overview: Trusted Publishing

HeroSD-JWT uses **NuGet Trusted Publishing** with OIDC authentication - the most secure method requiring **no long-lived API keys!**

**How it works:**

```
GitHub Actions (OIDC token)
    ↓
NuGet/login@v1 action
    ↓
NuGet.org (exchanges OIDC token for temporary 1-hour API key)
    ↓
dotnet nuget push (uses temporary key)
    ↓
✅ Package Published!
```

**Security Benefits:**
- ✅ No long-lived API keys to manage or rotate
- ✅ Temporary keys expire automatically (1 hour)
- ✅ Fine-grained access control tied to specific repository/workflow
- ✅ Better audit trail

### One-Time Setup

#### Step 1: Configure NuGet.org Trusted Publishing Policy

1. **Sign in to NuGet.org**: https://www.nuget.org/
2. **Navigate to Trusted Publishing**:
   - Click your username (top-right)
   - Select **Trusted Publishing**
3. **Create new policy**:
   - Click **Create new policy**
   - Fill in these **exact** values:
     ```
     Repository Owner:    KoalaFacts
     Repository Name:     HeroSD-JWT
     Workflow File:       publish-nuget.yml
     Environment:         production
     ```
   - Click **Create**

**Policy Status:**
- Shows "Temporarily Active" for 7 days
- Becomes permanently active after first successful publish
- Expires if unused within 7 days (can recreate)

#### Step 2: Add GitHub Secret (NUGET_USERNAME)

1. Go to: https://github.com/KoalaFacts/HeroSD-JWT/settings/secrets/actions
2. Click **New repository secret**
3. Add secret:
   - **Name**: `NUGET_USERNAME`
   - **Value**: Your NuGet.org **username** (NOT email)
     - Find it at top-right when logged into NuGet.org
4. Click **Add secret**

**Why this secret?**
- Only used for the `NuGet/login@v1` action
- Not a sensitive credential (just your public username)
- Helps the action identify which NuGet account to use

#### Step 3: Create GitHub Production Environment

1. Go to: https://github.com/KoalaFacts/HeroSD-JWT/settings/environments
2. Click **New environment**
3. Name: `production` (must match exactly)
4. **(Recommended)** Configure protection rules:
   - ✅ **Required reviewers**: Add yourself
     - Provides manual approval gate before publishing
   - ✅ **Deployment branches**: Select "Selected branches"
     - Add `main` (only main branch can publish)
   - ⏱️ **Wait timer** (optional): Add delay if desired
5. Click **Save protection rules**

**Why use an environment?**
- Prevents accidental publishing from feature branches
- Requires manual approval (if reviewers configured)
- Matches the Trusted Publishing policy on NuGet.org
- Provides audit trail of all production deployments

---

## Publishing Methods

### Method 1: Automated Release (Recommended) ⭐

This is the fully automated method with changelog generation:

#### Step 1: Update Version

Edit `src/HeroSdJwt/HeroSdJwt.csproj`:

```xml
<PropertyGroup>
  <Version>1.0.8</Version>
  <PackageReleaseNotes>
    Version 1.0.8:
    - Fixed critical security issue in digest validation
    - Performance improvements for large claim sets
    - Updated dependencies
  </PackageReleaseNotes>
</PropertyGroup>
```

#### Step 2: Update CHANGELOG.md

Add entry at the top:

```markdown
## [1.0.8] - 2025-11-06

### Fixed
- Fixed critical security issue in digest validation (#145)

### Changed
- Optimized claim path parsing for 40% faster performance

### Security
- Updated dependency versions to address vulnerabilities
```

#### Step 3: Commit Changes

```bash
git add src/HeroSdJwt/HeroSdJwt.csproj CHANGELOG.md
git commit -m "chore: bump version to 1.0.8

- Update version to 1.0.8 in project file
- Add changelog entries for security fix and performance improvements
- Update package release notes

Fixes: #145"

git push origin main
```

#### Step 4: Create and Push Tag

```bash
# Create annotated tag (preferred for releases)
git tag -a v1.0.8 -m "Release v1.0.8

Security Fix:
- Fixed critical digest validation issue

Performance:
- 40% faster claim path parsing

Full changelog: https://github.com/KoalaFacts/HeroSD-JWT/blob/main/CHANGELOG.md#108---2025-11-06"

# Push tag to GitHub
git push origin v1.0.8
```

#### Step 5: Automated Process

GitHub Actions will automatically:

1. **Release Workflow** (`create-release.yml`):
   - Generate changelog from commit history
   - Create GitHub release with notes
   - Attach NuGet packages (.nupkg and .snupkg)

2. **Publish Workflow** (`publish-nuget.yml`):
   - Build and test the project
   - Validate package format
   - Generate package provenance attestation
   - Publish to NuGet.org (requires production environment approval)

#### Step 6: Monitor Progress

1. Go to **Actions** tab: https://github.com/KoalaFacts/HeroSD-JWT/actions
2. Watch "Create Release" workflow first
3. Then "Publish to NuGet" workflow
4. Approve in production environment if prompted

**Pro tip**: Use conventional commit messages for better changelogs:

```bash
git commit -m "feat: add support for nested claims"
git commit -m "fix: resolve timing attack vulnerability"
git commit -m "docs: update API documentation"
```

### Method 2: Manual Publish via Workflow Dispatch

For testing or manual releases:

1. Go to **Actions** tab
2. Select "Publish to NuGet" workflow
3. Click **Run workflow**
4. (Optional) Enter version number (leave blank to use `.csproj` version)
5. Click **Run workflow**
6. Approve deployment if prompted

### Method 3: Local Manual Publish (Emergency Only)

For emergency or local testing, you'll need a temporary API key:

```bash
# Build the package
dotnet pack src/HeroSdJwt/HeroSdJwt.csproj --configuration Release --output ./nupkg

# Publish to NuGet.org (requires API key from https://www.nuget.org/account/apikeys)
dotnet nuget push ./nupkg/HeroSD-JWT.1.0.8.nupkg \
  --source https://api.nuget.org/v3/index.json \
  --api-key YOUR_API_KEY
```

**⚠️ Warning**: Local publishing requires an API key. For security, use Trusted Publishing via GitHub Actions instead (Methods 1 or 2).

---

## Pre-Release Checklist

Before creating any release, verify:

### Code Quality
- [ ] All CI/CD tests passing on `main` branch
- [ ] No compiler warnings in Release build
- [ ] Code coverage meets minimum threshold
- [ ] All TODOs and FIXMEs addressed or documented

### Documentation
- [ ] README.md updated (if API changes)
- [ ] CHANGELOG.md updated with all changes
- [ ] XML documentation comments updated
- [ ] Migration guide written (for breaking changes)
- [ ] Examples updated (if API changes)

### Testing
- [ ] Unit tests passing (452+ tests)
- [ ] Integration tests passing
- [ ] Security tests passing
- [ ] Manual testing completed for new features
- [ ] Backwards compatibility verified (if applicable)

### Version Management
- [ ] Version number updated in `src/HeroSdJwt/HeroSdJwt.csproj`
- [ ] Package release notes updated in `.csproj`
- [ ] Git tag created with proper naming (v1.x.x)
- [ ] Tag message includes summary of changes

### NuGet Package
- [ ] Package metadata correct (author, description, tags)
- [ ] Icon.png included
- [ ] README.md included in package
- [ ] License file included
- [ ] Symbol package (.snupkg) will be generated

### Security
- [ ] No secrets in code or configuration
- [ ] Dependencies scanned for vulnerabilities (`dotnet list package --vulnerable`)
- [ ] Security-sensitive changes reviewed
- [ ] Trusted Publishing policy configured on NuGet.org

### Communication
- [ ] Release notes drafted
- [ ] Breaking changes clearly documented
- [ ] Upgrade instructions provided (if needed)
- [ ] Community notified (if applicable)

---

## Post-Publishing Verification

### Check NuGet.org

1. **Package page**: https://www.nuget.org/packages/HeroSD-JWT
2. Should show your new version within 5-10 minutes
3. Verify metadata (description, tags, license)
4. Check that symbol package (.snupkg) is present

### Test Installation

```bash
# Create test project
dotnet new console -n TestHeroSdJwt
cd TestHeroSdJwt

# Install the new version
dotnet add package HeroSD-JWT --version 1.0.8

# Restore and build
dotnet restore
dotnet build

# Verify it works
# (add simple code to test the package)
```

### Verify Package Provenance

- GitHub automatically generates package provenance attestations
- Visible in workflow artifacts and on NuGet.org
- Provides supply chain security

### Update Documentation

After successful publish:

- [ ] Update main README.md with new version badge (if applicable)
- [ ] Announce release in GitHub Discussions (if major release)
- [ ] Update any external documentation referencing version numbers

---

## Changelog Management

### CHANGELOG.md Format

Follow [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Feature in development but not released yet

## [1.0.8] - 2025-11-06

### Fixed
- Fixed critical security issue in digest validation (#145)

### Changed
- Optimized claim path parsing for 40% faster performance

### Security
- Updated dependency versions to address vulnerabilities

## [1.0.7] - 2025-10-22

### Added
- Support for custom hash algorithms
- Batch verification API

[Unreleased]: https://github.com/KoalaFacts/HeroSD-JWT/compare/v1.0.8...HEAD
[1.0.8]: https://github.com/KoalaFacts/HeroSD-JWT/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/KoalaFacts/HeroSD-JWT/compare/v1.0.6...v1.0.7
```

### Categories (Use in Order)

1. **Added** - New features
2. **Changed** - Changes in existing functionality
3. **Deprecated** - Soon-to-be removed features
4. **Removed** - Removed features
5. **Fixed** - Bug fixes
6. **Security** - Vulnerability fixes

### Writing Good Changelog Entries

**Good Examples**:
```markdown
- Added `VerifyBatch()` method for batch verification with 10x performance improvement (#145)
- Fixed digest validation failing for SHA-384 algorithm on Windows (#123)
- **BREAKING**: Removed deprecated `CreateSdJwt()` overload that accepted string keys
```

**Bad Examples**:
```markdown
- Fixed bug (❌ not specific enough)
- Updated code (❌ no context)
- Various improvements (❌ too vague)
```

---

## Git Tagging Strategy

### Tag Naming Convention

**Stable Releases**:
```bash
v1.0.0      # Stable release
v1.1.0      # Minor update
v2.0.0      # Major update
```

**Pre-releases**:
```bash
v2.0.0-alpha.1    # Alpha 1
v2.0.0-alpha.2    # Alpha 2
v2.0.0-beta.1     # Beta 1
v2.0.0-rc.1       # Release candidate 1
```

### Always Use Annotated Tags

```bash
# ✅ Good - Annotated tag (recommended)
git tag -a v1.0.8 -m "Release v1.0.8: Security fix and performance improvements"

# ❌ Bad - Lightweight tag (for temporary markers only)
git tag v1.0.8
```

**Why annotated tags?**
- Include author, date, and message
- Can be signed with GPG
- Show in GitHub release dropdown
- Better for auditing

### Tag Message Template

```bash
git tag -a v1.0.8 -m "Release v1.0.8

Security Fix:
- Fixed critical digest validation issue

Performance:
- 40% faster claim path parsing

Bug Fixes:
- Corrected SHA-384 digest validation

Breaking Changes: None

Full changelog: https://github.com/KoalaFacts/HeroSD-JWT/blob/main/CHANGELOG.md#108"
```

### Managing Tags

```bash
# List all tags
git tag

# List tags matching pattern
git tag -l "v1.*"

# Show tag details
git show v1.0.8

# Delete local tag
git tag -d v1.0.8

# Delete remote tag (careful!)
git push origin :refs/tags/v1.0.8

# Push single tag
git push origin v1.0.8

# Push all tags
git push origin --tags
```

---

## Troubleshooting

### Package Already Exists

**Error:** "Package already exists" or "409 Conflict"

**Cause:** You cannot replace an existing version on NuGet.org

**Solution:**
1. Bump the version number in `src/HeroSdJwt/HeroSdJwt.csproj`
2. Rebuild and republish

### Authentication Fails (Trusted Publishing)

**Error:** "Authentication failed" or "401 Unauthorized"

**Check NuGet.org policy:**
- Go to https://www.nuget.org/ → Username → Trusted Publishing
- Verify policy exists with correct values:
  - Owner: `KoalaFacts`
  - Repo: `HeroSD-JWT`
  - Workflow: `publish-nuget.yml`
  - Environment: `production`
- Policy status should be "Active" or "Temporarily Active"

**Check GitHub secret:**
- Settings → Secrets and variables → Actions
- Verify `NUGET_USERNAME` exists
- Must be your NuGet.org **username**, not email
- No typos or extra spaces

**Check GitHub environment:**
- Settings → Environments
- Environment named `production` must exist
- If using protection rules, ensure deployment is approved

**Check workflow permissions:**
- Workflow has `id-token: write` permission (already configured)

### Tests Fail in CI

**Error:** "Tests failed in CI"

**Solution:**
1. Check GitHub Actions logs for specific errors
2. Run tests locally: `dotnet test --configuration Release`
3. Fix issues and push again
4. Ensure all dependencies are restored correctly

### Workflow Doesn't Trigger

**For automatic trigger (workflow_run):**
- `create-release.yml` must complete successfully first
- Check that tag was pushed to main branch
- Verify `workflow_run` trigger in `publish-nuget.yml`

**For manual trigger:**
- Ensure you have workflow trigger permissions
- Check repository settings allow workflow dispatch

### Bad Package Published to NuGet

**You cannot delete or replace a published version on NuGet.org!**

#### Option 1: Unlist (Preferred)

```bash
# Via NuGet.org web interface:
# 1. Go to package management page
# 2. Select the version
# 3. Click "Unlist"
```

Unlisted packages:
- Cannot be discovered in search
- Can still be installed if version is explicit
- Existing installations continue to work

#### Option 2: Publish Fixed Version

```bash
# Publish hotfix version immediately
v1.0.9 (fixes issues in v1.0.8)

# Communicate via:
# - GitHub release notes
# - NuGet package description
# - Community channels
```

### Bad Git Tag Pushed

```bash
# Delete remote tag
git push origin :refs/tags/v1.0.8

# Delete local tag
git tag -d v1.0.8

# Create corrected tag
git tag -a v1.0.8 -m "Release v1.0.8 (corrected)"
git push origin v1.0.8
```

⚠️ **Warning**: Only do this if package wasn't published yet!

---

## Best Practices

### DO ✅

- ✅ Use semantic versioning consistently
- ✅ Maintain detailed CHANGELOG.md
- ✅ Use annotated Git tags for releases
- ✅ Test thoroughly before releasing (run full test suite)
- ✅ Write clear, descriptive release notes
- ✅ Use Trusted Publishing with production environment
- ✅ Require manual approval for production deployments
- ✅ Keep release notes user-focused (not developer-focused)
- ✅ Include upgrade instructions for breaking changes
- ✅ Verify package installation after publishing
- ✅ Use conventional commits for better automated changelogs
- ✅ Always publish symbol packages (.snupkg) for debugging

### DON'T ❌

- ❌ Skip version bumps
- ❌ Release without updating CHANGELOG
- ❌ Use lightweight tags for releases
- ❌ Publish without testing
- ❌ Release on Friday afternoon (if avoidable)
- ❌ Include secrets or API keys in releases
- ❌ Rush releases under pressure
- ❌ Forget to update package metadata
- ❌ Mix multiple unrelated changes in one release
- ❌ Publish breaking changes in PATCH versions
- ❌ Use long-lived API keys (use Trusted Publishing instead)

---

## Quick Reference Commands

```bash
# Prepare release
git checkout main && git pull
dotnet test --configuration Release
dotnet build --configuration Release

# Update version in src/HeroSdJwt/HeroSdJwt.csproj
# Update CHANGELOG.md

# Commit changes
git add src/HeroSdJwt/HeroSdJwt.csproj CHANGELOG.md
git commit -m "chore: bump version to 1.0.8"
git push origin main

# Create and push tag
git tag -a v1.0.8 -m "Release v1.0.8"
git push origin v1.0.8

# Verify on NuGet.org (after GitHub Actions completes)
# https://www.nuget.org/packages/HeroSD-JWT/1.0.8
```

---

## Additional Resources

- **Semantic Versioning**: https://semver.org/
- **Keep a Changelog**: https://keepachangelog.com/
- **Conventional Commits**: https://www.conventionalcommits.org/
- **GitHub Releases**: https://docs.github.com/en/repositories/releasing-projects-on-github
- **NuGet Versioning**: https://learn.microsoft.com/en-us/nuget/concepts/package-versioning
- **Trusted Publishing**: https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package#trusted-publishing
- **NuGet Package**: https://www.nuget.org/packages/HeroSD-JWT
- **GitHub Actions**: https://github.com/KoalaFacts/HeroSD-JWT/actions

---

**Questions or Issues?** Open an issue at https://github.com/KoalaFacts/HeroSD-JWT/issues

**Last Updated:** 2025-11-06
**Maintainer:** KoalaFacts Team
