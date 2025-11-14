# Versioning Policy

**Purpose:** Define versioning strategy, API stability guarantees, and breaking change management for HeroSD-JWT
**Audience:** Maintainers, Contributors
**Last Updated:** 2025-01-07

---

## Table of Contents

- [Semantic Versioning](#semantic-versioning)
- [Version Format](#version-format)
- [API Stability Guarantees](#api-stability-guarantees)
- [Breaking Changes](#breaking-changes)
- [Deprecation Policy](#deprecation-policy)
- [Long-Term Support (LTS)](#long-term-support-lts)
- [.NET Version Support](#net-version-support)
- [Pre-Release Versions](#pre-release-versions)
- [Version Lifecycle](#version-lifecycle)
- [Migration Guides](#migration-guides)

---

## Semantic Versioning

HeroSD-JWT strictly follows [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

### Version Components

| Component | Increments When | Examples |
|-----------|----------------|----------|
| **MAJOR** | Breaking changes (incompatible API changes) | 1.0.0 → 2.0.0 |
| **MINOR** | New features (backward-compatible) | 1.0.0 → 1.1.0 |
| **PATCH** | Bug fixes (backward-compatible) | 1.0.0 → 1.0.1 |
| **PRERELEASE** | Pre-release versions (alpha, beta, rc) | 1.1.0-beta.1 |
| **BUILD** | Build metadata (not used for precedence) | 1.0.0+20250107 |

### Examples

```
✅ VALID:
1.0.0         - Major release
1.1.0         - Minor release (new features)
1.0.1         - Patch release (bug fixes)
2.0.0-alpha.1 - Pre-release
1.0.0+sha.5114f85 - Build metadata

❌ INVALID:
v1.0.0        - No 'v' prefix in version number
1.0           - Missing patch version
1.0.0.1       - Too many components
```

---

## Version Format

### NuGet Package Version

```xml
<PropertyGroup>
  <Version>1.0.0</Version>
  <PackageVersion>1.0.0</PackageVersion>
  <AssemblyVersion>1.0.0.0</AssemblyVersion>
  <FileVersion>1.0.0.0</FileVersion>
</PropertyGroup>
```

**AssemblyVersion Policy:**
- **MAJOR.0.0.0** - Only MAJOR version in AssemblyVersion (e.g., `1.0.0.0`, `2.0.0.0`)
- This allows MINOR and PATCH updates without breaking binary compatibility

### Git Tags

```bash
# Format: vMAJOR.MINOR.PATCH
git tag v1.0.0
git tag v1.1.0-beta.1
```

---

## API Stability Guarantees

### Public API Surface

**Guaranteed Stable (No breaking changes without MAJOR version bump):**

1. **Public Classes and Interfaces:**
   - `SdJwtBuilder`
   - `ISdJwtIssuer`, `ISdJwtVerifier`, `ISdJwtPresenter`
   - `SdJwt`, `VerificationResult`, `ReconstructedClaims`
   - `SdJwtException`, `ErrorCode` enum

2. **Public Extension Methods:**
   - `ToPresentation()`, `ToPresentationWithAllClaims()`
   - `IServiceCollection` extensions (ASP.NET Core)

3. **Configuration Types:**
   - `SdJwtVerificationOptions`
   - `SdJwtAuthenticationOptions`

4. **Public Constants:**
   - Algorithm names (HS256, RS256, ES256, EdDSA)
   - Hash algorithm names (SHA-256, SHA-384, SHA-512)
   - Reserved claim names

**Not Guaranteed Stable (Can change in MINOR versions):**

1. **Internal Types:**
   - Types marked `internal`
   - Types in `Internal/` namespace

2. **Experimental Features:**
   - APIs marked with `[Experimental]` attribute
   - Features documented as "preview" or "beta"

3. **Performance Characteristics:**
   - Execution time, memory usage (can improve in MINOR/PATCH)

4. **Error Messages:**
   - Exception message text (can change for clarity)

### Binary Compatibility

**Guaranteed:**
- MINOR and PATCH releases maintain binary compatibility
- Existing compiled applications work without recompilation

**Not Guaranteed:**
- MAJOR version changes may break binary compatibility
- Pre-release versions have no compatibility guarantees

---

## Breaking Changes

### What is a Breaking Change?

**Breaking changes include:**

1. **API Removal:**
   - Removing public types, methods, properties, or extension methods
   - Removing enum values

2. **Signature Changes:**
   - Changing method signatures (parameters, return types)
   - Changing property types
   - Changing accessibility (e.g., public → internal)

3. **Behavioral Changes:**
   - Changing default values that affect behavior
   - Throwing new exceptions in existing methods
   - Changing validation rules (making them stricter)

4. **Dependency Changes:**
   - Increasing minimum .NET version requirement
   - Adding third-party dependencies (breaks zero-dependency guarantee)

**NOT breaking changes:**

1. **Adding new APIs:**
   - New types, methods, properties, overloads
   - New optional parameters with defaults

2. **Bug Fixes:**
   - Fixing incorrect behavior (even if code relied on bug)

3. **Performance Improvements:**
   - Optimizations that don't change behavior

4. **Error Message Changes:**
   - Improving exception messages

5. **Internal Changes:**
   - Refactoring internal implementation

### Breaking Change Process

**Before introducing a breaking change:**

1. **RFC (Request for Comments):**
   - Create GitHub Discussion with `[RFC] Breaking Change:` prefix
   - Explain rationale, alternatives considered, migration path
   - Gather community feedback (minimum 2 weeks)

2. **Deprecation Period:**
   - Deprecate old API for at least 6 months before MAJOR release
   - Mark with `[Obsolete]` attribute with descriptive message
   - Document in deprecation log

3. **Migration Guide:**
   - Create detailed migration guide before MAJOR release
   - Include before/after code examples
   - Document automated migration tools (if available)

4. **Major Version Release:**
   - Bundle breaking changes into MAJOR releases
   - Release at most 1-2 times per year

---

## Deprecation Policy

### Deprecation Timeline

```
┌─────────────┬──────────────┬─────────────┬──────────────┐
│  v1.5.0     │   v1.6.0     │   v1.7.0    │    v2.0.0    │
├─────────────┼──────────────┼─────────────┼──────────────┤
│ Feature     │ Deprecation  │ Warning     │ Removal      │
│ Introduced  │ Announced    │ Warnings    │ (Breaking)   │
│             │ [Obsolete]   │ in Logs     │              │
└─────────────┴──────────────┴─────────────┴──────────────┘
    ←────────── Minimum 6 months ──────────→
```

### Deprecation Process

1. **Announce Deprecation (MINOR release):**
   ```csharp
   [Obsolete("Use NewMethod() instead. This will be removed in v2.0.0.")]
   public void OldMethod() { ... }
   ```

2. **Update Documentation:**
   - Mark API as deprecated in XML docs
   - Add migration guide to docs
   - Update CHANGELOG.md with deprecation notice

3. **Runtime Warnings:**
   - Emit warnings during usage via exceptions or return values (optional, for critical deprecations)

4. **Removal (MAJOR release):**
   - Remove deprecated API in next MAJOR version
   - Document removal in CHANGELOG.md
   - Include migration instructions in release notes

### Obsolete Attribute Usage

```csharp
// ✅ CORRECT - Clear message with version
[Obsolete("Use SdJwtBuilder.SignWithHmac() instead. Removed in v2.0.0.", error: false)]
public SdJwt SignWithHS256(byte[] key) { ... }

// ❌ WRONG - Vague message, no version
[Obsolete("Don't use this.")]
public void SomeMethod() { ... }
```

---

## Long-Term Support (LTS)

### LTS Policy

**Definition:** LTS versions receive security fixes and critical bug fixes for extended periods.

| Version Type | Support Duration | Updates Provided |
|--------------|------------------|------------------|
| **LTS** | 12 months from release | Security fixes, critical bugs |
| **Non-LTS** | 6 months from release | Security fixes only |

### LTS Version Schedule

**Aligned with .NET LTS releases:**

| HeroSD-JWT Version | .NET Target | LTS Status | Support End Date |
|--------------------|-------------|------------|------------------|
| 1.x | .NET 8.0 (LTS) | ✅ LTS | November 2026 (.NET 8 EOL) |
| 2.x | .NET 10.0 (LTS) | 🔮 Planned | November 2028 (projected) |

### LTS Support Includes

✅ **Included:**
- Security vulnerability fixes
- Critical bug fixes (data loss, crashes)
- .NET security patch compatibility

❌ **NOT Included:**
- New features
- Performance improvements
- Non-critical bug fixes
- Deprecations

### Patch Release Cadence

- **Security fixes:** Released immediately (within 7-14 days)
- **Critical bugs:** Released within 30 days
- **Minor bugs:** Bundled into quarterly patch releases

---

## .NET Version Support

### Multi-Targeting Strategy

HeroSD-JWT targets multiple .NET versions to maximize compatibility:

```xml
<TargetFrameworks>net8.0;net9.0</TargetFrameworks>
```

### .NET Version Support Policy

| .NET Version | HeroSD-JWT Support | Notes |
|--------------|-------------------|-------|
| .NET 9.0 | ✅ Supported | Current release, STS (18 months) |
| .NET 8.0 | ✅ Supported (LTS) | LTS until November 2026 |
| .NET 7.0 | ❌ Not Supported | Reached EOL May 2024 |
| .NET 6.0 | ❌ Not Supported | Reaches EOL November 2024 |

### Adding New .NET Versions

**MINOR version** - Add support for new .NET versions:
```
Example: v1.5.0 adds .NET 10.0 support
```

### Dropping .NET Versions

**MAJOR version** - Drop support for EOL .NET versions:
```
Example: v2.0.0 drops .NET 8.0 (after EOL in November 2026)
```

**Exception:** If dropping .NET version before EOL, requires:
- RFC with 6-month notice
- Documented rationale (e.g., new C# features required)
- Community consensus

---

## Pre-Release Versions

### Pre-Release Stages

```
Alpha → Beta → Release Candidate (RC) → Stable
```

| Stage | Stability | Purpose | Breaking Changes Allowed? |
|-------|-----------|---------|---------------------------|
| **Alpha** | Experimental | Early testing, API exploration | ✅ Yes |
| **Beta** | Feature-complete | Testing, bug fixes | ⚠️ Rare |
| **RC** | Production-ready | Final testing | ❌ No |
| **Stable** | Production | General availability | ❌ No |

### Pre-Release Version Format

```
MAJOR.MINOR.PATCH-STAGE.NUMBER

Examples:
2.0.0-alpha.1
2.0.0-alpha.2
2.0.0-beta.1
2.0.0-rc.1
2.0.0          # Stable release
```

### Pre-Release Guarantees

- ⚠️ **No API stability guarantees** between pre-release versions
- ⚠️ **No LTS support** for pre-release versions
- ✅ **Security fixes provided** if critical
- ❌ **Not recommended for production** (alpha, beta)
- ✅ **Production-ready** (RC only)

---

## Version Lifecycle

### Typical Release Cycle

```
┌──────────────────────────────────────────────────────────┐
│                   Version 1.x Lifecycle                   │
├──────────────────────────────────────────────────────────┤
│  v1.0.0 (Stable)                                          │
│    ↓                                                      │
│  v1.1.0 (New Features)                                    │
│    ↓                                                      │
│  v1.2.0 (New Features)                                    │
│    ↓                                                      │
│  v1.3.0-alpha.1 (Early Access to v2 features)             │
│    ↓                                                      │
│  v2.0.0-beta.1 (Breaking Changes Preview)                 │
│    ↓                                                      │
│  v2.0.0-rc.1 (Release Candidate)                          │
│    ↓                                                      │
│  v2.0.0 (Stable, Breaking Changes)                        │
└──────────────────────────────────────────────────────────┘
```

### Version Support Matrix

| Version | Released | EOL Date | Status |
|---------|----------|----------|--------|
| 1.0.x | 2024-Q4 | 2026-11 | ✅ Supported (LTS) |
| 2.0.x | 2026-Q1 (planned) | 2028-11 | 🔮 Planned |

---

## Migration Guides

### Migration Guide Requirements

Every MAJOR version release **must** include:

1. **Migration Guide Document:**
   - Location: `docs/migration/v1-to-v2.md`
   - Format: Markdown with code examples

2. **Content:**
   - Breaking changes summary
   - Step-by-step migration instructions
   - Before/after code comparisons
   - Common pitfalls and solutions
   - Estimated migration time

3. **Automated Tools (if applicable):**
   - Roslyn analyzers to detect deprecated API usage
   - Code fix providers for automated migration

### Example Migration Guide Structure

```markdown
# Migration Guide: v1.x to v2.0

## Breaking Changes Summary
- Removed: `OldMethod()`
- Renamed: `SomeClass` → `BetterClass`
- Changed: `MethodSignature(int)` → `MethodSignature(long)`

## Step-by-Step Migration

### 1. Update NuGet Package
\`\`\`bash
dotnet add package HeroSD-JWT --version 2.0.0
\`\`\`

### 2. Replace Deprecated APIs

**Before (v1.x):**
\`\`\`csharp
var result = jwt.OldMethod();
\`\`\`

**After (v2.0):**
\`\`\`csharp
var result = jwt.NewMethod();
\`\`\`

...
```

---

## Enforcement

### Pull Request Checklist

Before merging changes, verify:

- [ ] Version number follows SemVer 2.0.0
- [ ] Breaking changes are in MAJOR release only
- [ ] Deprecated APIs have `[Obsolete]` attribute
- [ ] CHANGELOG.md is updated
- [ ] Migration guide created (if MAJOR release)
- [ ] XML documentation updated
- [ ] API stability tests pass

### Automated Checks

CI/CD enforces:
- ✅ Package validation (`dotnet pack --verify`)
- ✅ Public API analyzer (detects breaking changes)
- ✅ Contract tests (API stability verification)

---

## Exceptions

### Emergency Patches

In rare cases, **critical security vulnerabilities** may require:
- Immediate patch release (within 24-48 hours)
- Bypassing normal deprecation timeline

**Requirements:**
- Documented justification
- Approval from 2+ maintainers
- Security advisory published

---

## References

- **Semantic Versioning 2.0.0:** https://semver.org/
- **.NET Support Policy:** https://dotnet.microsoft.com/en-us/platform/support/policy
- **NuGet Package Versioning:** https://learn.microsoft.com/en-us/nuget/concepts/package-versioning

---

## Questions?

For versioning policy questions:
- **GitHub Discussions:** https://github.com/KoalaFacts/HeroSD-JWT/discussions
- **Maintainers:** See [CODEOWNERS](../.github/CODEOWNERS)

---

**Version:** 1.0
**Approved By:** Lead Maintainer
**Next Review:** 2026-01-07
