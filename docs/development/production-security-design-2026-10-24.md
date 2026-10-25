# Production authentication security fixes

## Intent

Close the production blockers reproduced on main `7ef4e8cd33ae2767e3b9501a861a0b627bf29de7` on 2026-10-24. The user authorized implementation after reviewing the findings and priorities.

## Required behavior

- The public `AddSdJwt` authentication registration must enforce each scheme's issuer, audiences, key type, clock skew, hash algorithm, and holder key-binding options. Policies from different schemes must not leak into one another.
- Failed signature, claims, disclosure, key-binding, or reconstruction checks must not consume replay identifiers. A valid presentation can consume its identifier exactly once.
- Distributed replay admission must use a backend atomic create-if-absent operation with expiration. Unsupported generic caches must fail closed, never claim cross-process replay protection.
- Key-binding verification must compute `sd_hash` using the credential's `_sd_alg` and explicitly accept only the implemented ES256 holder-signature algorithm.
- Existing valid issuer/presenter/verifier and documented customization paths must continue working, or an unavoidable security-related compatibility change must be explicit and tested.

## Approach

Fix the public registration and verifier lifecycle at their source and add regression tests through the real public APIs. Keep stateful replay admission after all read-only validation. Introduce an explicit atomic backend capability for the distributed adapter; ordinary `IDistributedCache.GetAsync/SetAsync` cannot satisfy that contract.

Alternatives considered: process-local locking cannot protect multiple servers; duplicating verification in the authentication handler would add overhead and two competing policy paths; silently ignoring scheme options or accepting non-atomic caches preserves the demonstrated vulnerabilities. Use a single correctly configured verification path and an explicit backend contract instead.

## Constraints

- Preserve the existing net8.0/net9.0/net10.0 targets and locked dependencies unless an isolated optional backend integration requires an explicit addition.
- Keep the core library BCL-only. Use the existing xUnit tests.
- Do not silently replace historical benchmark data or weaken performance acceptance.
- Do not claim .NET 11, NativeAOT, full RFC conformance, or production release acceptance from these targeted fixes.
- Extend existing PR #72 by explicitly merging inspected head `22d6c05197656318eaa47b0986cba69547fd975c` and its concurrent successor `8b57d5901baf23deb9a44fb993f34f67213cb0f4` into the reviewed security branch. Preserve its complete history, disclosure/digest fixes and meaningful tests; incorporate it rather than overwrite it. The original isolated task evidence remains historical, and final gates apply to the merged result.

## Review priorities

Scheme isolation, custom verifier compatibility, dependency lifetimes, replay side effects after malformed input, atomic TTL behavior, and independent SHA-384/SHA-512 key-binding fixtures.

## Delivery

One consolidated, reviewed security-fix branch with failing-before/passing-after test evidence. Final acceptance includes a clean locked restore, Release tests, formatting, and package consumption where the environment permits. Shipping remains subject to the existing performance gate and final release validation.
