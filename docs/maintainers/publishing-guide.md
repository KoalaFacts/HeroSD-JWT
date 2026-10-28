# Publishing HeroSD-JWT

Maintainer runbook, checked against the release workflows on 29 October 2026. At this review the latest GitHub Release was **v1.1.7**; **2.0.0 has not been published**. These instructions do not authorize a release.

## Normal release: current main → GitHub Release → NuGet

1. Review the **exact main SHA** and its Build/Test, Security and local-package consumer results. Queued/cancelled jobs are not passes. Review [the upgrade guide](../users/upgrading-to-2.0.md) and `CHANGELOG.md` before a major release.
2. An authorized maintainer selects `main` and enters an explicit version such as `2.0.0` in [Actions → Create Release](https://github.com/KoalaFacts/HeroSD-JWT/actions/workflows/create-release.yml). **Do not push a tag manually.**
3. `create-release.yml` verifies that the checked-out SHA is still remote main and that the release tag is absent. It performs locked restore, Release build, tests, packs the **core** `HeroSD-JWT.<version>.nupkg`/`.snupkg` and smoke-tests installation of the packed package on **.NET 8/9/10**.
4. That workflow records the source SHA and both SHA-256 package digests in the **release-identity** artifact, generates per-framework SBOMs, then creates the GitHub Release/tag with auto-generated notes and a package-installation footer.
5. Successful completion triggers `publish-nuget.yml` via `workflow_run`. The automatic path reads the **exact triggering run's** identity artifact, checks release tag → source SHA, downloads the named assets and compares both package hashes **before** attestation, OIDC NuGet login or publishing. The publish job uses the `production` environment and NuGet Trusted Publishing.
6. Verify the **exact published version** on [NuGet.org](https://www.nuget.org/packages/HeroSD-JWT/), including package metadata and symbols; install it into an independent consumer from NuGet.org to confirm actual distribution. The pre-release smoke tests only verify a locally packed package.

This workflow currently publishes only the **HeroSD-JWT core package**, not a separately packed `HeroSdJwt.AspNetCore` package. It **does not automatically edit or commit `CHANGELOG.md`**. Release notes are generated from GitHub and appended with a footer.

The input validator accepts `MAJOR.MINOR.PATCH` or a single alphanumeric suffix, e.g. `2.0.0-rc`. Dotted pre-release identifiers such as `2.0.0-rc.1` are **not supported by the current workflow regex**. NuGet's wider SemVer support does not mean this workflow accepts it.

## Required publishing configuration

On NuGet.org, Trusted Publishing must match owner `KoalaFacts`, repository `HeroSD-JWT`, workflow `publish-nuget.yml` and environment `production`. The GitHub Actions secret `NUGET_USERNAME` must hold the **NuGet account username**, not a long-lived API key. The workflow requests `id-token: write` for temporary OIDC credentials and `attestations: write` for provenance. Review the real production environment approval and allowed-branch rules before publishing; do not assume they are enabled.

## Emergency manual republish

The **Publish to NuGet** workflow also supports `workflow_dispatch` for an existing GitHub Release. Enter the desired version explicitly (blank input fails runtime validation despite its optional UI label).

**Manual dispatch is not equivalent to the automatic path.** It intentionally skips loading the original release-identity artifact and skips automatic tag/source-SHA and packed-asset hash checks. It only selects the named Release and validates package presence. Independently verify the exact immutable source and package asset digests before authorizing an emergency republish. Do not use this exception for normal first publication.

Do not invoke **Create Release** merely to inspect readiness: it creates a real GitHub Release and can trigger NuGet publishing. Do not delete/recreate tags or substitute assets to repair a failed publication. NuGet versions are immutable; correct defects in a new version.

## Practical verification / failures

- **CI evidence**: `ci.yml` runs .NET 8/9/10 across Windows/Linux/macOS, code-quality/format, dependency review and packed-package consumer tests. Compare checks to the exact release SHA and distinguish queued from passed.
- **Security**: review `scan-security.yml` for that same source SHA; failure must be investigated, not bypassed.
- **Performance**: retain BenchmarkDotNet raw data. Missing job provenance in historical samples is **INCONCLUSIVE**, not a pass or regression; the valid-data **105%** threshold remains in place.
- **Create Release fails**: inspect main-SHA check, locked restore, tests, smoke, package presence and SBOM generation. Fix via PR and re-dispatch only after confirming the Release/tag was not created.
- **Publish fails**: inspect source-run identity, tag SHA, both package hash checks, NuGet policy, `NUGET_USERNAME` and production approval. If NuGet already contains the version, investigate before choosing a corrected version.
- **Consumer installation fails**: verify the exact NuGet.org version and follow [the 1.1.7 → 2.0 upgrade guide](../users/upgrading-to-2.0.md).

Source of truth: [Create Release workflow](../../.github/workflows/create-release.yml), [Publish workflow](../../.github/workflows/publish-nuget.yml), [CI](../../.github/workflows/ci.yml), [changelog](../../CHANGELOG.md).
