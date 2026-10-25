# Production security validation — 2026-10-24

## Scope and source identity

This records local validation of the consolidated security implementation that continues existing PR [#72](https://github.com/KoalaFacts/HeroSD-JWT/pull/72). It preserves the disclosure, scheme-policy, replay and key-binding work from remote heads `22d6c051` and `8b57d590`, and adds complete per-scheme policy factories, scoped dependencies, reconstruction before replay admission, configured hash constraints, and atomic distributed cache requirements.

The local production build/test/package checkpoint is `5b4c2889cf8661410d5fa7d1b0a2ce5616ae0c67`. The `src` tree is `f8ad716a82788d68bd1a8ed56f01be3c1cdc657a`; the test tree used for the complete matrix is `0759f0bf584e2c8eeccb13c09358479a0791e12f`. Later test-only formatting and documentation updates do not change that production source. Implementation/checkpoint commit IDs in the plan are local review identifiers; external delivery binds the final content tree to the actual PR head, without rewriting existing PR history.

SDK 10.0.402 and the installed .NET 8.0.32, 9.0.21 and 10.0.13 runtimes were used on Linux x64. All eight tracked dependency lock files are byte-unchanged from main `7ef4e8cd33ae2767e3b9501a861a0b627bf29de7`.

## Build and complete test matrix

Normal audited locked restore passed. The complete Release solution build, including examples and benchmarks, passed with explicit `TreatWarningsAsErrors=true`: zero warnings and zero errors. An earlier parallel build encountered MSBuild worker exits (`MSB4166`); serial builds completed without changing compiler, analyzer or warning requirements.

| Runtime target | Core passed | ASP.NET passed | Failed | Existing manual-load skips |
| --- | ---: | ---: | ---: | ---: |
| net8.0 | 1223 | 65 | 0 | 5 |
| net9.0 | 1223 | 65 | 0 | 5 |
| net10.0 | 1223 | 65 | 0 | 5 |

There are **1,288 passing cases per target**, or **3,864 successful framework executions**, not 3,864 distinct tests. The five load tests skipped on each target are existing manual tests; no load/soak acceptance is claimed.

Commands (the two test projects were run separately on each target, with unique TRX result names):

```bash
dotnet restore HeroSD-JWT.slnx --locked-mode -m:1 -nr:false
dotnet build HeroSD-JWT.slnx -c Release --no-restore -m:1 -nr:false -p:UseSharedCompilation=false -p:TreatWarningsAsErrors=true
dotnet test tests/HeroSdJwt.Tests/HeroSdJwt.Tests.csproj -c Release -f net8.0 --no-build --no-restore -m:1 -nr:false --logger trx
dotnet test tests/HeroSdJwt.AspNetCore.Tests/HeroSdJwt.AspNetCore.Tests.csproj -c Release -f net8.0 --no-build --no-restore -m:1 -nr:false --logger trx
# Repeat both test commands for net9.0 and net10.0.
dotnet format HeroSD-JWT.slnx --verify-no-changes --no-restore
```

The first complete formatting check identified a redundant qualification in `AuthenticationPolicyTests` and an unannotated JSON literal in an imported KB test. Test-only commit `349e542` (integrated as `f41d197`) adds an import/name simplification and embedded JSON annotation, with no semantic or assertion changes. The two covering net10.0 test groups passed 27/27 and 7/7, and the actual complete verify-only formatter then passed with exit 0 and no diagnostics. Production source is byte-identical to the matrix/package checkpoint; no diagnostics are suppressed and no test assertions are removed.

## Independent review and integration

Independent reviews approved each of the authentication, verifier and atomic-cache tasks. The authentication review requested explicit derived-verifier migration coverage, which was added and re-reviewed. A whole-branch review approved `7ef4e8cd..ef13903`; a follow-up approved the complete PR #72 integration through `5b4c288`. No introduced Critical, Important or Minor defect requiring revision remained in those reviews.

All 21 original disclosure boundary cases and both replay cases are retained unchanged. All eight original scheme-policy cases remain; the explicit-registration cases now configure the authoritative scheme policy, preserve rejection/lazy-dependency checks, and add actual validator reuse plus template nonmutation. All seven incoming key-binding cases and their assertions are retained, with compilation/style repairs. The compatibility decision is explicit in [authentication migration](../users/authentication-policy.md).

## Actual NuGet package consumer

Both packages were packed locally as **1.1.8-security-validation**, a validation-only version that was not published. They contain the original net8.0/net9.0/net10.0 assets. A separate net10.0 console project outside the repository restored the ASP.NET package by `PackageReference` from this local feed into a fresh NuGet cache, with no project references. Its loaded core and ASP.NET assemblies were hash-matched to the net10 assets inside the candidate packages.

| Candidate package | SHA-256 |
| --- | --- |
| `HeroSD-JWT.1.1.8-security-validation.nupkg` | `71f05f9617a2374e1b30eac778556bcebf4f6320809a3fae9cbd69d8b294d179` |
| `HeroSD-JWT.AspNetCore.1.1.8-security-validation.nupkg` | `c3180d6225f095eb8a467bf005c78d2acfe89b7498bacccb865f1ac8438307e3` |

| Packaged asset | SHA-256 |
| --- | --- |
| `lib/net10.0/HeroSdJwt.dll` | `09b8503d6e9e996d8213ee8338e00df76d3d63d0e96e9c33688b76074edcde5c` |
| `lib/net8.0/HeroSdJwt.dll` | `f7f94d79b9e2020420748671b68ba7b1f7c2c71189c85df3c93d7181e514b6e5` |
| `lib/net9.0/HeroSdJwt.dll` | `0c4b040a131566e37754f4202d088c98f639b714c344026338f4bd7d2af2b9bd` |
| `lib/net10.0/HeroSdJwt.AspNetCore.dll` | `d1085d4c1431d728dfe3e8ad6dafeccc6a85d13865394ebad7e6a19029db3f0b` |
| `lib/net8.0/HeroSdJwt.AspNetCore.dll` | `462aab2cc5fd4f2dff358431d3f3bf4f6a3a8e0c894093c7ae44a9d1ae9545b6` |
| `lib/net9.0/HeroSdJwt.AspNetCore.dll` | `375b08b691962f046ab621b5bab42a1561cff0bcddd1884747e8727eb4605b03` |

The consumer composes `AddSdJwtDistributedReplayProtection`, `AddSdJwt` and the default verifier through public DI, with a directly registered `InMemoryJtiCache`. This proves helper-to-verifier-to-authentication wiring and the documented custom-cache hook. It is not a distributed backend or Redis/SQL durability test.

Actual output:

```text
PASS wrong issuer rejected
PASS wrong audience rejected
PASS invalid signature rejected
PASS invalid signature leaves replay state unchanged
PASS genuine first use accepted
PASS genuine second use rejected
PASS missing holder proof rejected
PASS non-atomic distributed cache fails closed
PASS actual NuGet candidate consumer: 8 checks
```

Both pack commands, the clean consumer restore and its Release execution exited 0. Reproduction commands after building the repository, using a local feed directory of your choice:

```bash
dotnet pack src/HeroSdJwt/HeroSdJwt.csproj -c Release --no-build --no-restore -o /tmp/herosd-candidate-packages -p:Version=1.1.8-security-validation -p:PackageVersion=1.1.8-security-validation
dotnet pack src/HeroSdJwt.AspNetCore/HeroSdJwt.AspNetCore.csproj -c Release --no-build --no-restore -o /tmp/herosd-candidate-packages -p:Version=1.1.8-security-validation -p:PackageVersion=1.1.8-security-validation
# In a separate directory containing the two consumer files below:
dotnet restore Consumer.csproj --source /tmp/herosd-candidate-packages
dotnet run --project Consumer.csproj --no-restore -c Release
```

The recorded pack invocation also set `RepositoryCommit` to the local checkpoint above. That metadata is not a claim that a new release was published or the existing release workflow was repaired.

## Remaining production acceptance

- **Replay retention policy at the original 36ddf2c8 checkpoint:** `JtiValidator` capped marker TTL at `MaximumTtl` and used `DefaultTtl` for invalid/missing `exp`, potentially permitting later re-admission. A subsequent security follow-up changes admission to fail closed when a token lacks valid expiration or outlives the configured marker retention; see [distributed replay documentation](../users/distributed-replay-protection.md). The original validation counts above belong to the original source checkpoint and are not evidence that the follow-up passed the complete matrix. The replay validator remains stricter than general verification clock skew.
- **Actual distributed backend:** no atomic Redis/SQL provider is shipped or certified. Real cross-process concurrency, expiry, failover, eviction/durability and transport-error behavior must be verified for the selected backend. See [the backend contract and migration guide](../users/distributed-replay-protection.md).
- **Compatibility:** custom authentication verifiers need the explicit factory contract; subclasses must override it; verifier services are scoped. Constructor options formerly relied upon for authentication must be moved into each scheme. Existing distributed key markers require the documented coordinated migration or drain.
- **Historical performance acceptance:** ambiguous historical BenchmarkDotNet job identity remains unresolved. No row identities were guessed, original baseline replaced, samples discarded or 105% threshold weakened. Fresh hosted results must be associated with the actual updated PR head.
- **Release and broader assurance:** publishing must bind the tested source and intended packages; external interoperability, manual load/soak, AOT and release-pipeline acceptance remain separate. Previous .NET 11 RC receipts on an older PR head are not evidence for this consolidated source. No package publication or production deployment was performed.
- **Existing API limits:** Try-style async verification converts cancellation/errors into an invalid result; synchronous custom interfaces cannot accept cancellation tokens. Directly resolving the async DI alias against a sync-only custom verifier retains its preexisting cast limitation. Authentication itself checks and supports a synchronous factory product. Arbitrary custom factories and cache providers must honor their contracts; these fixtures cannot certify arbitrary implementations.

## Exact consumer files

Create these files outside the repository so that its build props do not alter the standalone package-consumption check.

### Consumer.csproj

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
    <PackageReference Include="HeroSD-JWT.AspNetCore" Version="1.1.8-security-validation" />
  </ItemGroup>
</Project>
```

### Program.cs

```csharp
using System.Security.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;
using HeroSdJwt.AspNetCore.Verification.ReplayProtection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;

using var trusted = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
const string issuer = "https://issuer.example.test";
const string audience = "https://api.example.test";
var replayOptions = new ReplayProtectionOptions { Enabled = true };
using var cache = new InMemoryJtiCache(replayOptions);
var services = new ServiceCollection();
services.AddLogging();
services.AddSingleton<IJtiCache>(cache);
services.AddSdJwtDistributedReplayProtection();
services.AddAuthentication("Candidate").AddSdJwt("Candidate", options =>
{
    options.FallbackKey = trusted.ExportSubjectPublicKeyInfo();
    options.VerificationOptions = new SdJwtVerificationOptions
    {
        ExpectedIssuer = issuer,
        ExpectedAudience = audience,
        ClockSkew = TimeSpan.Zero
    };
});
services.AddAuthentication().AddSdJwt("BoundCandidate", options =>
{
    options.FallbackKey = trusted.ExportSubjectPublicKeyInfo();
    options.VerificationOptions = new SdJwtVerificationOptions
    {
        ExpectedIssuer = issuer,
        ExpectedAudience = audience,
        RequireKeyBinding = true,
        ExpectedNonce = "fresh-transaction"
    };
});
using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
string Issue(string id, string actualIssuer, string actualAudience, ECDsa signer) =>
    SdJwtIssuerBuilder.Create().WithClaim("iss", actualIssuer).WithClaim("aud", actualAudience)
        .WithClaim("sub", "candidate-consumer").WithClaim("jti", id)
        .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds())
        .SignWithEcdsa(signer.ExportPkcs8PrivateKey()).Build().ToCombinedFormat();
async Task Check(string name, string token, bool expected, string scheme = "Candidate")
{
    using var scope = provider.CreateScope();
    var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
    context.Request.Headers.Authorization = "Bearer " + token;
    var result = await context.AuthenticateAsync(scheme);
    if (result.Succeeded != expected)
        throw new InvalidOperationException($"{name}: expected {expected}; actual {result.Succeeded}; {result.Failure}");
    Console.WriteLine($"PASS {name}");
}
await Check("wrong issuer rejected", Issue("issuer-case", "https://wrong.example.test", audience, trusted), false);
await Check("wrong audience rejected", Issue("audience-case", issuer, "https://wrong.example.test", trusted), false);
var valid = Issue("signature-case", issuer, audience, trusted);
await Check("invalid signature rejected", Issue("signature-case", issuer, audience, other), false);
if (await cache.ExistsAsync(issuer, "signature-case"))
    throw new InvalidOperationException("An invalid signature consumed the replay identifier");
Console.WriteLine("PASS invalid signature leaves replay state unchanged");
await Check("genuine first use accepted", valid, true);
await Check("genuine second use rejected", valid, false);
await Check("missing holder proof rejected", Issue("binding-case", issuer, audience, trusted), false, "BoundCandidate");
var cacheServices = new ServiceCollection();
cacheServices.AddDistributedMemoryCache();
using var cacheProvider = cacheServices.BuildServiceProvider();
try
{
    _ = new DistributedJtiCache(cacheProvider.GetRequiredService<IDistributedCache>());
    throw new InvalidOperationException("Non-atomic distributed cache was accepted");
}
catch (NotSupportedException)
{
    Console.WriteLine("PASS non-atomic distributed cache fails closed");
}
Console.WriteLine("PASS actual NuGet candidate consumer: 8 checks");
```
