# Production Security Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development. Each task requires failing regression tests before implementation and a review of the resulting change.

**Goal:** Close the reproduced authentication-policy and replay-protection gaps and the identified key-binding verification gaps.

**Architecture:** Apply authentication scheme options to the verifier actually handling that scheme. Admit replay identifiers only after successful read-only validation. Require an atomic distributed backend capability, with no get-then-set fallback.

**Tech Stack:** C#, .NET 8/9/10, ASP.NET Core, xUnit.

**Spec:** `docs/development/production-security-design-2026-10-24.md`

## Global Constraints

- Keep the core library BCL-only and preserve existing supported target frameworks.
- Use existing xUnit tests; no unrelated framework migration.
- Preserve locked dependency versions unless a new optional integration explicitly needs a dependency.
- No inferred historical benchmark identity, baseline replacement, or weakened thresholds.
- Extend existing PR #72 by merging its current head explicitly; preserve all existing PR commits, meaningful disclosure/digest fixes and tests. Do not overwrite other branches or user work.

## Review Focus

- Multiple authentication schemes must retain distinct policies and scoped services.
- Custom verifier implementations must have explicit, safe policy semantics.
- Every failed validation path must leave replay state unchanged.
- Duplicate concurrent admission must have exactly one winner and keep its TTL.
- A standard-generated key-binding proof with SHA-384/SHA-512 must verify correctly.

### Task 1: Enforce authentication scheme policy

Files: `src/HeroSdJwt.AspNetCore/Authentication/`, related ASP.NET registration/factory files, and a new `tests/HeroSdJwt.AspNetCore.Tests/Integration/AuthenticationPolicyTests.cs`.

Interfaces: retain the public `AddSdJwt` registration API; select a scheme-aware verifier construction/configuration path without mutating shared default options. Coordinate shared DI registration edits with Task 3.

- [x] Add real public-registration tests for wrong issuer, wrong audience, missing required KB, key-type selection, clock skew, valid controls, and distinct schemes. No replacement of the default verifier in these tests.
- [x] Run the new tests and record their expected failures.
- [x] Apply the scheme options through the verification pipeline; cover customized services and replay/revocation registration.
- [x] Run all ASP.NET tests and review compatibility and dependency lifetimes.
- [x] Commit the task with its validation evidence.

### Task 2: Prevent invalid presentations consuming replay state; enforce KB algorithm semantics

Files: `src/HeroSdJwt/Verification/SdJwtVerifier.cs`, `src/HeroSdJwt/KeyBinding/KeyBindingValidator.cs`, new security/regression tests under `tests/HeroSdJwt.Tests/`.

Interfaces: public verifier methods and replay-cache APIs remain compatible. Reuse existing digest-algorithm resolution and avoid changing unrelated signature algorithms.

- [x] Add failing tests showing an invalid issuer signature, claims, digest, or KB cannot consume a valid token's replay identifier.
- [x] Move replay admission after all validation and disclosure reconstruction; retain exactly-once valid behavior.
- [x] Add independent KB fixtures for `_sd_alg` SHA-256, SHA-384 and SHA-512, plus missing/unsupported/none KB `alg` values with valid cryptographic signatures.
- [x] Fix KB digest selection and fail closed on unsupported header algorithms.
- [x] Run the complete core tests, including legitimate replay and revocation scenarios, then commit.

### Task 3: Make distributed replay admission atomic

Files: `src/HeroSdJwt.AspNetCore/Verification/ReplayProtection/`, related DI extension, distributed-cache tests and usage documentation; an optional backend integration only if needed for a working concrete provider.

Interfaces: preserve `IJtiCache`. `DistributedJtiCache` must require a backend operation with atomic add-if-absent and TTL semantics; it must fail closed for an ordinary non-atomic `IDistributedCache`.

- [x] Reproduce the concurrent duplicate-admission failure with the real adapter and a controlled thread-safe cache.
- [x] Implement an explicit atomic capability and a practical provider integration or documented direct `IJtiCache` integration. Do not implement a custom Redis wire protocol.
- [x] Test exactly one winner, TTL preservation/expiry, cancellation and backend failures. Use a real backend for any newly shipped backend provider.
- [x] Document the security-related compatibility requirement, test DI resolution, and commit.

### Task 4: Integrate and deliver

- [x] Combine the reviewed task commits and resolve any DI overlap.
- [x] Run locked restore, Release build/tests, formatting, and an actual-package consumer smoke test.
- [x] Have an independent reviewer inspect the complete change and address material findings.
- [ ] Push one security-fix branch and create/update its reviewable PR; inspect current hosted checks and report exact remaining gates.

## Execution ledger

External publication and current hosted check receipts are tracked on existing PR #72; this file records the prepared source checkpoint before that external write.

- Baseline: main `7ef4e8cd`; prior-turn net10.0 validation 1,173 passed, 5 existing manual-load skips. Three runtime security probes independently reproduced by the coordinator.
- Ruling: use independent worktrees for parallel implementation; integration and final verification are sequential to avoid shared source/build state.
- Ruling: the user's instruction to proceed authorizes these reversible implementation choices; no additional design-confirmation round is needed.
- Task 1: implemented in `65bbb3d`, integrated as `549f900`; public-registration RED was 11 failures / 8 controls, then 23 focused passes and 53 complete ASP.NET passes. Independent task review approved the implementation with one low compatibility-test follow-up.
- Task 1 follow-up: `e77e1a8`, integrated as `f6a43f2`; added four derived-verifier migration cases and public migration documentation. Fresh focused 4/4 and complete ASP.NET 57/57 passed. Scoped independent review marks the original finding ADDRESSED, with no new important defects.
- Task 2: implemented in `bfa3ec8` and `5058ccd`, integrated as `4c18b74` and `db0f5f8`; original RED 21/24 failures, cancellation RED 1/1, hash-policy RED 3/4. Final focused 32/32 and complete core 1,175 passed / 5 existing skips on net10.0. Independent spec/security review approved with no required revisions.
- Ruling: configured `ExpectedHashAlgorithm` and an explicit per-call constraint are additive policy requirements; the actual algorithm must satisfy both. An explicit argument cannot weaken configured policy, and contradictory constraints reject.
- Task 3: implemented in `b9099f3`, integrated as `372677b`; the old adapter admitted 32/32 concurrent duplicates and the old key format had two reproduced tuple collisions. Updated tests cover one atomic winner, original TTL, cancellation/errors, DI and key isolation. Isolated full net10.0 run: core 1,161 passed / 5 existing skips, ASP.NET 30 passed. Independent spec/security review approved. No concrete distributed backend is shipped or certified by these fixture results.
- Task 4: DI overlap auto-merged and was inspected. Normal audited locked solution restore passed. The initial parallel build ended with MSBuild worker exits (`MSB4166`); serial full-solution Release build passed all targets with zero warnings/errors. Consolidated tests, final formatting, package-consumer validation, whole-branch review and hosted checks follow separately; isolated task totals are not combined-branch evidence.

- Integration ruling (2026-10-24): fresh remote inspection found PR #72 at `22d6c05197656318eaa47b0986cba69547fd975c`, including overlapping authentication/replay work after the initially inspected `a02a69f`. Extend that existing PR by explicitly merging it into the reviewed security branch at `ef13903`; PR #72 is incorporated, not overwritten or replaced. Retain its disclosure binding fixes and regression cases alongside the stricter public factory contract, scoped dependencies, reconstruction-before-JTI admission and atomic backend requirements. Earlier isolated evidence remains historical and does not certify the merged result.
- Compatibility ruling before adapting `SchemePolicyRegressionTests.Should_PreserveExplicitVerifierPolicy`: authentication schemes supply the complete authoritative policy for factory products; source verifier constructor options are standalone defaults, not hidden additional policy. The old test's empty-scheme override expectation is intentionally superseded. Migrate the test to explicitly configure issuer/KB on each scheme while retaining rejection, dependency reuse and unused-default-collaborator assertions; add differing-policy and source-nonmutation coverage. Users who relied on constructor policy must move it into each scheme, and custom restrictions must be retained explicitly by their factory.
- Integration implementation choice: remove PR #72's internal `AuthenticationVerifierFactory`; the reviewed public `ISdJwtVerifierFactory` path supersedes it, retains all configured validators/replay/revocation dependencies and enforces policy for explicit custom registrations. The internal ownership test would otherwise preserve a silent scheme-policy bypass and omit replay/revocation collaborators.
- PR #72 integration verification: fresh audited locked restore passed after allowing network access to NuGet. Focused merged Release/net10.0 tests passed: core 83/83 (21 disclosure binding, 2 legacy replay admission, 32 verification admission/KB/hash/cancellation, 28 atomic-cache/registration/key-isolation), ASP.NET 35/35 (8 existing scheme cases, 27 reviewed authentication-policy cases); no failures or skips. `git diff --check` passed. Full three-framework tests, formatting, actual-package consumer and whole-branch review remain coordinator gates.
- Concurrent PR #72 integration ruling: the remote advanced to `8b57d5901baf23deb9a44fb993f34f67213cb0f4` (parent `22d6c05`) during the first merge. Incorporate it in a second explicit merge, retaining all seven added key-binding conformance cases and history. Combine its stricter object/string JOSE header guards into one ES256/kb+jwt check; retain the reviewed UTF-8 hash input and algorithm switch (ASCII is equivalent for valid compact tokens but may replace invalid non-ASCII input). No policy or validation weakening is authorized.
- Concurrent-head verification: the incoming conformance test had three `Encoding.ASCII` namespace-binding compile errors and two constant-style warnings; qualify `System.Text.Encoding.ASCII` and use uppercase constants without changing cases/assertions. Fresh focused Release/net10.0 passed 39/39 (7 incoming conformance cases plus 32 admission/KB/hash/cancellation cases), with no warnings/failures/skips. No full suite repeat was run in this integration worktree.
- Final source checkpoint `5b4c288`: audited locked restore passed; complete Release solution build with explicit `TreatWarningsAsErrors=true` passed with zero warnings/errors. Full net8.0, net9.0 and net10.0 suites each passed 1,223 core + 65 ASP.NET cases, with five existing manual-load skips and zero failures. This is 3,864 successful target executions, not 3,864 distinct cases. All eight lock files remain unchanged.
- Whole-branch review: `7ef4e8cd..ef13903` approved for code/spec; scoped integration review `ef13903..5b4c288` also approved with no introduced Critical/Important/Minor defect requiring revision. These are source approvals, not completion of external production gates.
- Final formatting follow-up: complete formatter reported `IDE0002` on one qualified encoder name and `JSON002` on an imported explicit JSON literal. Test-only commit `349e542`, integrated as `f41d197`, adds an import/name simplification and embedded JSON annotation (+3/-2 across two files). Covering net10 tests passed 27/27 and 7/7; the actual full solution verify-only formatter passed exit 0 with no diagnostics. Assertions, diagnostics, production source and dependencies are unchanged; no full matrix repeat was needed for these semantic-preserving test edits.
- Actual candidate consumption: both locally packed `1.1.8-security-validation` packages restored via a separate net10 PackageReference consumer with no project references; all eight public-registration/security checks passed. Both loaded assemblies match the package assets by SHA-256. No publication occurred. Complete commands, exact consumer, package/assembly hashes and boundaries are in `docs/development/production-security-validation-2026-10-24.md`.
- Ruling: defer the preexisting replay-retention/accepted-credential-lifetime mismatch to the next production policy task. Atomic admission remains guaranteed only while a marker is live; defaults can permit later re-admission for accepted credentials outliving the marker. The ongoing monitor must address this before claiming lifetime-wide replay protection. The cost of deferral is that current tests do not certify that broader property.
- Deferred review boundaries: existing Try-method cancellation conversion, direct async-alias casts for sync-only custom verifiers, arbitrary custom provider correctness, real backend durability, performance provenance, release-chain SHA binding, AOT/load and independent interoperability remain explicit follow-up gates. PR #72 disclosure work is now incorporated and reviewed; no full RFC conformance claim follows from its boundary tests.
- Final style re-review: approved `5b4c288..f41d197`; IDE0002/JSON002 findings are addressed with no semantic changes or suppressions. Reviewer inspected the empty full-format log, covering test evidence and actual package-consumer/hash summary, and found no documentation misstatement requiring correction. All requested local gates are satisfied; external publication/current hosted checks remain separately recorded on PR #72.
