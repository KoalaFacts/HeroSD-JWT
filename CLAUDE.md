# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

HeroSD-JWT is a .NET library implementing **SD-JWT** (Selective Disclosure for JSON Web Tokens) per the IETF `draft-ietf-oauth-selective-disclosure-jwt` spec. It lets an issuer mint credentials whose individual claims can be selectively revealed by a holder and cryptographically verified by a verifier, without disclosing the rest.

Two shipped packages:
- **`HeroSdJwt`** (`src/HeroSdJwt`) — the core library. Zero third-party runtime dependencies (BCL only; .NET 8 adds the `Microsoft.Bcl.Memory` polyfill for `Base64Url`). Multi-targets `net8.0;net9.0;net10.0` and is AOT-compatible.
- **`HeroSdJwt.AspNetCore`** (`src/HeroSdJwt.AspNetCore`) — DI registration, an authentication handler, and distributed (`IDistributedCache`-backed) replay-protection / revocation adapters.

## Build, Test, Format

The solution uses the modern `.slnx` format (`HeroSD-JWT.slnx`).

```bash
dotnet restore HeroSD-JWT.slnx
dotnet build HeroSD-JWT.slnx --configuration Release
dotnet test                                   # all tests, all target frameworks
dotnet test --framework net10.0               # single TFM (much faster while iterating)
dotnet format --verify-no-changes             # CI fails the build if this reports changes
```

Run a single test or a subset by fully-qualified name (see test note below — trait/category filters do **not** work here):

```bash
dotnet test --filter "FullyQualifiedName~AlgorithmSecurityTests"
dotnet test --filter "FullyQualifiedName~SdJwtVerifierTests.Should_RejectNoneAlgorithm"
```

Run benchmarks (BenchmarkDotNet — requires Release):

```bash
dotnet run -c Release --project benchmarks/HeroSdJwt.Benchmarks -- --filter '*'
```

### Build settings that bite (defined in `Directory.Build.props`)
- **`TreatWarningsAsErrors=true`** and **`EnforceCodeStyleInBuild=true`** for `src/` — analyzer warnings and `.editorconfig` style violations fail the build. (Relaxed for `*.Tests`/`*.Benchmarks` projects.)
- **`RestoreLockedMode=true`** with `packages.lock.json` in every project. If you add/upgrade a `PackageReference`, a normal `restore` fails; regenerate locks with `dotnet restore --force-evaluate`.
- **`Nullable`** and **`ImplicitUsings`** are enabled. Target frameworks come from `$(SupportedTargetFrameworks)` in `Directory.Build.props` — change versions there, not in individual `.csproj` files.

## Architecture

The code is organized by the three-party SD-JWT roles. Data flows: **Issuance → Presentation → Verification**.

### Core pipeline (`src/HeroSdJwt`, root namespace `HeroSdJwt`)

- **`Issuance/`** — `SdJwtIssuer` (low-level `CreateSdJwt(...)`) composes `IDisclosureGenerator`, `IDigestCalculator`, `IDecoyDigestGenerator`, and `IJwtSigner`. `NestedClaimProcessor` handles `address.street` / `degrees[1]`-style selective-disclosure paths. `SdJwtIssuerBuilder` is the fluent front door (`.WithClaim().MakeSelective().SignWithHmac/Rsa/Ecdsa/Ed25519().Build()`). Note: an `exp` claim is auto-added (default +5 min) if absent.
- **`Presentation/`** — `SdJwtPresenter.CreatePresentation(...)` selects which disclosures to reveal; `DisclosureClaimPathMapper` / `DisclosureParser` map claim paths to disclosure blobs. The wire format is `JWT~disclosure1~...~disclosureN~[keyBinding]` (`SdJwtPresentation.ToCombinedFormat()`).
- **`Verification/`** — `SdJwtVerifier` is the heart. It implements **both** `ISdJwtVerifier` (sync) and `ISdJwtVerifierAsync` on one instance, and orchestrates `ISignatureValidator`, `IDigestValidator`, `IKeyBindingValidator`, `IClaimValidator`. It offers `VerifyPresentation` (throws) and `TryVerifyPresentation` (returns `VerificationResult` with `.IsValid`/`.Errors`). `SdJwtVerifierBuilder` wires it up. Key rotation is handled via a `KeyResolver` delegate (`kid` → key) with optional `fallbackKey`; `KeyIdGuard`/`KeyIdValidator` harden `kid` before resolution.
  - **`Verification/ReplayProtection/`** — `JtiValidator` + `IJtiCache` (`InMemoryJtiCache` default). Optional; disabled when not injected.
  - **`Verification/Revocation/`** — `IRevocationStore` (`InMemoryRevocationStore` default). Optional.
- **`Cryptography/`** — `JwtSigner` (sign/verify for HS/RS/ES/EdDSA), `KeyGenerator` (`KeyGenerator.Instance`), `EcPublicKeyConverter`. ECDSA signatures use JOSE raw `R||S` form, not ASN.1 DER.
- **`KeyBinding/`** — RFC 7800 proof-of-possession (`cnf`) generation/validation with temporal checks.
- **`Models/`** — `SdJwt`, `Disclosure`, `Digest`, `ClaimPath`, `VerificationResult` (carries disclosed claims + reconstruction helpers like `GetDisclosedObject` / `GetDisclosedArray`).
- **`Primitives/`** — enums and constants: `SignatureAlgorithm` (HS256, RS256, ES256, EdDSA), `HashAlgorithm` (SHA-256/384/512), `VerificationKeyType`, `ErrorCode`, `KeyResolver`.
- **`Internal/Ed25519/`** — a self-contained, constant-time Ed25519 implementation (BCL has no managed EdDSA across all TFMs). Treat as a vendored crypto primitive; don't casually refactor.

Everything is built around **constructor-injected interfaces** — the implementations are stateless and thread-safe, so they're registered as singletons. When adding a component, follow the `IFoo` + `Foo` + DI-registration pattern.

### ASP.NET Core layer (`src/HeroSdJwt.AspNetCore`)
- `AddSdJwtServices()` (in `SdJwtServiceCollectionExtensions`, deliberately under namespace `Microsoft.Extensions.DependencyInjection`) registers the whole pipeline. `AddSdJwtDistributedReplayProtection()` / `AddSdJwtDistributedRevocation()` swap the in-memory adapters for `IDistributedCache`-backed ones. The auth handler prefers the async verification path when available.
- `Authentication/SdJwtAuthenticationHandler` plugs SD-JWT verification into ASP.NET Core's auth scheme model.

## Conventions

- **No third-party runtime dependencies** in the core library — use only `System.Security.Cryptography`, `System.Text.Json`, `System.Buffers.Text`. Adding a package to `HeroSdJwt` is a deliberate architectural decision.
- **AOT/trim-safe**: internal JSON uses `Utf8JsonWriter` and direct dictionary parsing, not reflection-based serialize/deserialize. Reflection is confined to the API boundary where users pass `Dictionary<string, object>` claim values; those sites are explicitly guarded with `#pragma warning disable IL2026, IL3050`. Keep new code in this style.
- **Security-critical comparisons** use `CryptographicOperations.FixedTimeEquals`; salts/keys use `RandomNumberGenerator`. The `"none"` algorithm is rejected (upper and lower case). Verification defaults `ExpectedKeyType = Asymmetric` to prevent alg/key confusion.
- **Public APIs require XML doc comments** (`GenerateDocumentationFile=true`); missing docs are build errors in `src/`.
- **Branch naming**: `feature/…`, `fix/…`, `docs/…`, `refactor/…`, `test/…`. Commits follow Conventional Commits (`feat(scope): …`, `fix(scope): …`).

## Tests

- xUnit **v3** (`xunit.v3`). Property-based tests use **CsCheck**, fake data uses **Bogus**, load tests use **NBomber**.
- Two test projects: `tests/HeroSdJwt.Tests` (core) and `tests/HeroSdJwt.AspNetCore.Tests`. Internals are exposed via `InternalsVisibleTo("HeroSdJwt.Tests")`.
- Tests are organized **by folder/namespace**, not xUnit traits: `Unit/`, `Integration/`, `Contract/`, `Scenarios/`, `Security/`, `Fuzz/`, `Load/`, plus `Verification/ReplayProtection/`. The README's `--filter "Category=Integration"` examples do not match any traits in this repo — filter by `FullyQualifiedName~<Namespace-or-ClassName>` instead.
- Test naming convention: `Should_ExpectedBehavior_When_Condition`.

## CI

`.github/workflows/ci.yml` runs build + test across the matrix of {ubuntu, windows, macOS} × {net8.0, net9.0, net10.0}, plus a **Code Quality** job that builds with warnings-as-errors and runs `dotnet format --verify-no-changes`, plus a dependency-review job. Run `dotnet format` and a full `dotnet test` before pushing — formatting and analyzer drift are the most common CI failures. Other workflows: nightly integration (`run-integrations.yml`), security scanning (`scan-security.yml`), benchmarks (`perform-benchmarks.yml`), NuGet publish and release (`publish-nuget.yml`, `create-release.yml`).
