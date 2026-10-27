# Verification API

These additive entry points are **development-source additions**. They are not a claim that the currently published NuGet version contains them. Import `HeroSdJwt.Verification` to use them with a builder-created `SdJwtVerifier`, `ISdJwtVerifier`, or `ISdJwtVerifierAsync` resolved through dependency injection.

## Choose one failure contract

| Entry point | Verification failure | Cancellation |
| --- | --- | --- |
| `Verify` / `VerifyAsync` | Throws `SdJwtException`; never returns an invalid result | Propagates `OperationCanceledException` |
| `TryVerify` / `TryVerifyAsync` | Returns `VerificationResult` with `IsValid == false` and error codes | Propagates `OperationCanceledException` |

Each name has direct-key and key-resolver overloads. Async methods forward the caller's token and recheck it when the verification operation completes. They await the existing async pipeline without `Task.Run`, synchronous blocking or an additional verification pass. The `KeyResolver` delegate itself remains synchronous; this change does **not** add asynchronous key retrieval.

`Try` means expected verification errors are represented by a result, not that every exception is suppressed. Null arguments still throw `ArgumentNullException` (synchronously, including async entry points). Unexpected implementation errors propagate. Do not translate cancellation into an authentication failure response. Do not log complete credentials, keys, or raw backend exception details.

## Issue, present and verify

The following console example uses an asymmetric issuer key and explicitly configures the verifier policy. Keep issuer private keys separate from verifier public keys in real applications.

```csharp
using HeroSdJwt.Cryptography;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

var (privateKey, publicKey) = KeyGenerator.Instance.GenerateEcdsaKeyPair();
var credential = SdJwtIssuerBuilder.Create()
    .WithClaim("iss", "https://issuer.example.test")
    .WithClaim("aud", "https://verifier.example.test")
    .WithClaim("sub", "user-123")
    .WithClaim("email", "alice@example.test")
    .MakeSelective("email")
    .SignWithEcdsa(privateKey)
    .Build();

var presentation = credential.ToPresentation("email");
ISdJwtVerifierAsync verifier = SdJwtVerifierBuilder.Create()
    .WithExpectedKeyType(VerificationKeyType.Asymmetric)
    .WithExpectedIssuer("https://issuer.example.test")
    .WithExpectedAudience("https://verifier.example.test")
    .Build();

using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
var result = await verifier.TryVerifyAsync(
    presentation, publicKey, cancellationToken: timeout.Token);

if (!result.IsValid)
{
    Console.WriteLine(string.Join(", ", result.Errors));
    return;
}

Console.WriteLine(result.DisclosedClaims["email"].GetString());
```

Use `VerifyAsync` instead when the caller prefers catching `SdJwtException`. Both forms retain the exact configured issuer/audience, key-type, key-binding, revocation and replay policies; none is enabled or disabled by selecting a new entry point. The result must be valid before reading disclosed claims.

## Key rotation

Pass your existing key resolver and the request cancellation token:

```csharp
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

// publicKeys is the application's trusted key-ID-to-public-key dictionary.
KeyResolver resolveKey = keyId => publicKeys.GetValueOrDefault(keyId);
var result = await verifier.TryVerifyAsync(
    presentation,
    resolveKey,
    cancellationToken: cancellationToken);
```

A fallback key is used only when `kid` is absent. An unrecognized `kid` remains `KeyIdNotFound`; it does not silently fall back to another trusted key. Pass `expectedHashAlgorithm:` only to add a per-call hash constraint; it cannot relax the verifier's configured hash policy.

## ASP.NET Core and custom implementations

Continue registering services and authentication schemes as before. An injected `ISdJwtVerifierAsync` can call `TryVerifyAsync(..., cancellationToken: HttpContext.RequestAborted)` without constructing a second verifier or discarding scoped services. This change does not alter authentication-handler registration or behavior.

Custom implementations need not implement any additional interface members. Extension methods call the existing `VerifyPresentation` / `VerifyPresentationAsync` overload exactly once, preserving dependency lifetimes and side effects. They normalize either a returned invalid result or a thrown `SdJwtException`. They deliberately do not call the legacy Try methods because those methods can suppress cancellation.

## Compatibility and migration

Existing `VerifyPresentation*` / `TryVerifyPresentation*` signatures, defaults and behavior remain unchanged. There are no new abstract interface members, obsolete warnings, dependency changes or package releases in this change.

Migrate one call site at a time:

```csharp
// Result-first API: cancellation is not converted into InvalidInput.
var result = await verifier.TryVerifyAsync(
    presentation, publicKey, cancellationToken: cancellationToken);

// Throwing API: a returned failed result is also converted to SdJwtException.
var verified = await verifier.VerifyAsync(
    presentation, publicKey, cancellationToken: cancellationToken);
```

The existing async `VerifyPresentationAsync` can return an invalid result even though its legacy XML summary describes a throwing method. New `VerifyAsync` removes that ambiguity without silently changing existing callers. `TryVerify*` catches only `SdJwtException`, unlike the legacy broad exception conversion. A returned `VerificationResult` is preserved; its `ErrorDetails` are diagnostic data, not a public response. Exceptions converted by the new Try entry points retain their error code but use a generic failure message.
