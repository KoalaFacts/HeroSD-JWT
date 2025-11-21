# Changelog

## [Unreleased]

- Align ECDSA handling with JWS spec: ES256/384/512 signatures are emitted as JOSE raw R||S and verifiers accept JOSE format.
- Signature verification hardening: Algorithm/key-type guardrails with default `ExpectedKeyType` tightened to `Asymmetric` (set to `Symmetric` for HS*).
- Added builder hook `.WithExpectedKeyType(...)` for configuring key-type policy via `SdJwtVerifierBuilder`.
- Added async verification APIs (`ISdJwtVerifierAsync`) so replay protection and revocation checks no longer block when using async caches/stores.
- ASP.NET handler now prefers async verification when available; in-memory revocation cleanup loop moved to non-blocking `PeriodicTimer`.
- Multi-audience verification: configure multiple expected audiences via `ExpectedAudiences`/`WithExpectedAudiences(...)` with matching enforcement for key binding JWTs.
- Key resolver robustness: verifier now rejects empty/too-long/non-printable `kid` values before calling the resolver or revocation checks, surfacing dedicated key ID error codes (also in Try* flows).

## [1.1.7] - 2025-11-20

See [GitHub Release](https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.1.7) for details.


## [1.1.6] - 2025-11-20

See [GitHub Release](https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.1.6) for details.


## [1.1.5] - 2025-11-20

See [GitHub Release](https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.1.5) for details.


## [1.1.4] - 2025-11-20

See [GitHub Release](https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.1.4) for details.


## [1.1.3] - 2025-11-14

See [GitHub Release](https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.1.3) for details.


## [1.1.2] - 2025-11-14

See [GitHub Release](https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.1.2) for details.


All notable changes to this project are documented in the [GitHub Releases](https://github.com/KoalaFacts/HeroSD-JWT/releases) page.

## [1.1.1] - 2025-11-14

See [GitHub Release](https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.1.1) for details.

## [1.1.0] - 2025-11-14

See [GitHub Release](https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.1.0) for details.

## [1.0.7] - 2025-11-03

See [GitHub Release](https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.0.7) for details.

## [1.0.0] - 2025-01-21

See [GitHub Release](https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.0.0) for details.

