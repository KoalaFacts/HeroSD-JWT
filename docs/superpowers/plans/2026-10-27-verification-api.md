# Consistent verification entry points

> Implement inline; the user has authorized routine implementation without another approval round.

**Goal:** Offer a concise, consistent verification API without changing existing interface members, constructor wiring, defaults or legacy method behavior.

**Architecture:** Add extension methods in HeroSdJwt.Verification for ISdJwtVerifier and ISdJwtVerifierAsync. Invoke each existing throwing pipeline exactly once. Verify/VerifyAsync never return an invalid result; TryVerify/TryVerifyAsync convert SdJwtException to VerificationResult. Cancellation and unexpected implementation exceptions propagate. Async entry points validate null arguments synchronously and check cancellation before and after invoking the existing pipeline. Hash policy, resolver and fallback arguments are forwarded unchanged.

**Tech stack:** Existing C#/.NET 8/9/10, xUnit v3, no dependency or lockfile changes.

**Approaches:** Changing the existing abstract interfaces or silently changing legacy exception behavior would break custom implementations or callers. A new service/factory would duplicate configuration and lifetimes. Additive extension methods are the selected compatibility approach; the legacy API stays available and no deprecation warning is introduced.

**Spec:** docs/users/verification-api.md (API contract and migration examples).

## Implementation
- [x] Write interface-level contract tests and real signed-credential tests before implementation.
- [x] Add Verify, TryVerify, VerifyAsync and TryVerifyAsync; each has direct-key and resolver overloads.
- [x] Add coverage for error-code preservation, null arguments, missing/unknown kid, hash-policy forwarding, cancellation before/after callbacks, and custom verifier compatibility.
- [x] Add usage examples and state clearly that new APIs are development-source additions, not already in the published package.
- [ ] Run exact-head Release build, tests, formatting and dependency/security checks through existing CI. Local .NET execution is unavailable: no SDK is installed and the container cannot resolve GitHub hosts. Tests-first commit is not an executed RED claim.
- [ ] Review the exact diff and retain one focused PR; never publish a NuGet package as part of this change.
