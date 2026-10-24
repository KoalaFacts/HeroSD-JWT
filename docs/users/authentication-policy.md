# Authentication scheme policies and custom verifiers

`AddSdJwt` applies the complete `VerificationOptions` policy belonging to the selected authentication scheme. Configure issuer, accepted audiences, key type, clock skew, disclosure hash algorithm and holder key-binding requirements on that scheme. Each scheme receives its own verifier policy; registering a standalone verifier with different options does not replace the scheme policy.

```csharp
builder.Services.AddAuthentication("credentials")
    .AddSdJwt("credentials", options =>
    {
        options.FallbackKey = issuerPublicKey;
        options.VerificationOptions = new SdJwtVerificationOptions
        {
            ExpectedIssuer = "https://issuer.example",
            ExpectedAudiences = ["https://api.example"],
            ExpectedKeyType = VerificationKeyType.Asymmetric,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });
```

This example uses `HeroSdJwt.Primitives`, `HeroSdJwt.Verification` and `Microsoft.AspNetCore.Authentication`. `issuerPublicKey` is the issuer's verification key. Use `KeyResolver` when resolving rotating signing keys. Set `ExpectedKeyType = VerificationKeyType.Symmetric` explicitly when accepting HMAC credentials.

If holder key binding is required, also configure `RequireKeyBinding = true`, an expected audience and the expected nonce for the holder challenge. A presentation must then contain a valid holder proof matching that policy.

## Existing `SdJwtVerifier` registrations

The concrete `SdJwtVerifier` implements `ISdJwtVerifierFactory`. Existing registrations of that concrete type support scheme policies automatically. Its `CreateVerifier(SdJwtVerificationOptions)` method creates a separate verifier with the supplied policy while retaining its configured signature, digest, key-binding and claim validators, `JtiValidator` and revocation store. It does not modify the source verifier's options.

This is a compatibility change for authentication registrations that previously relied on options passed to the verifier constructor. Move those issuer, audience, key-binding and other authentication requirements into `VerificationOptions` on **each** scheme. The constructor options remain the policy for direct standalone calls; factory products use the complete scheme policy, even when it differs from those defaults. Additional custom restrictions implemented by validators, wrappers or subclasses must be preserved by the factory alongside the supplied scheme policy.

Keep replay and revocation dependencies when customizing construction. In the default `AddSdJwtServices` registration, explicitly registered `JtiValidator` and `IRevocationStore` services are resolved from the current service scope. A standalone `IJtiCache` registration does not by itself enable replay checking: configure an enabled `JtiValidator` or use the replay registration helper. Distributed replay storage must meet the atomic admission requirements described in the replay protection documentation.

## Custom `ISdJwtVerifier` implementations

A custom verifier used by `AddSdJwt` must implement **both** `ISdJwtVerifier` and `ISdJwtVerifierFactory`. Authentication fails closed, with a configuration message naming `ISdJwtVerifierFactory`, when this explicit capability is missing. Implementing the original verification interface alone remains sufficient for callers that use that verifier directly outside authentication.

The factory contract is:

```csharp
ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions options);
```

Apply the complete supplied policy. Do not return a shared verifier with unrelated options, ignore policy fields or mutate a shared verifier to switch between schemes. Preserve customized validation behavior, security dependencies and their configured lifetimes. A factory may return a verifier implementing `ISdJwtVerifierAsync`; the authentication handler prefers that asynchronous pipeline and passes `HttpContext.RequestAborted`. Synchronous custom verifiers remain supported, but their existing synchronous interface has no cancellation-token parameter.

For an existing wrapper around a concrete `SdJwtVerifier`, a typical factory method can derive the inner verifier and wrap it with the same customization:

```csharp
// Inside an existing CustomVerifier wrapper that implements both interfaces.
// This assumes its constructor accepts the inner verifier and a custom policy.
public ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions options)
{
    var innerForScheme = _inner.CreateVerifier(options);
    return new CustomVerifier(innerForScheme, _customPolicy);
}
```

The wrapper's verification methods must continue applying `_customPolicy` to the newly configured inner verifier. If the wrapper implements the asynchronous interface, retain it on the returned wrapper as well.

## Subclasses of `SdJwtVerifier`

A subclass inherits the factory interface, but must **override `CreateVerifier`** explicitly. The base implementation rejects derived runtime types because constructing a plain `SdJwtVerifier` could discard subclass behavior. The authentication failure message identifies the required override.

The override should construct the customized type with the supplied scheme options and the dependencies required to preserve its behavior. Keep references to those dependencies in the subclass constructor so that they can be reused safely. For example, the shape of an override is:

```csharp
public override ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions options)
{
    return new CustomSdJwtVerifier(
        options,
        _signatureValidator,
        _digestValidator,
        _keyBindingValidator,
        _claimValidator,
        _keyConverter,
        _jtiValidator,
        _revocationStore,
        _customPolicy);
}
```

This is an illustrative constructor shape for your subclass; retain the actual dependencies and behavior your implementation uses. Calling `base.CreateVerifier(options)` from a subclass still encounters the base runtime-type guard. Returning `this` without applying the supplied options would leave the authentication scheme's policy unenforced.

Verify the migration through `AddSdJwt`: accept a valid credential, reject an incorrect issuer or audience, and reject a credential that violates the custom rule. Include multiple schemes and request scopes if the custom verifier serves them.

## Dependency lifetimes

The default `ISdJwtVerifier` registration and its `ISdJwtVerifierAsync` alias are now **scoped**. Both interfaces resolve to the same default instance within one scope; different scopes receive different instances. This allows custom scoped validators, replay validators and revocation stores to remain within the request that owns them. Built-in cryptographic/claim validators, issuer and presenter retain their existing singleton defaults.

Resolve the default verifier within a request or an explicitly created scope. Code that previously captured it in a singleton should instead create a scope for the operation or move the consuming service to an appropriate scoped lifetime. Existing custom `ISdJwtVerifier` registrations retain their declared lifetime because registration uses `TryAdd`; a custom singleton still requires every captured dependency to be safe for that singleton lifetime.

```csharp
using var scope = serviceProvider.CreateScope();
var verifier = scope.ServiceProvider.GetRequiredService<ISdJwtVerifier>();
```

Do not retain a verifier beyond the scope that owns its dependencies. Factory products retain those dependencies too, so complete their use within that same scope.

## KB-JWT audience wire format (RFC 9901)

A holder's **signed Key Binding JWT** must contain exactly one string-valued
`aud` claim. RFC 9901 Section 4.3 requires a **single string**, unlike the
general-purpose JWT audience array allowed by RFC 7519. A KB-JWT with an
array-valued `aud` is rejected even when an element matches the verifier.

This is an intentional conformance-tightening change. An application can still
configure multiple **acceptable verifier audiences** (via `ExpectedAudiences`);
the proof must select exactly one of them for its string-valued `aud`.
When upgrading, regenerate any nonconforming holder proofs with a single
audience rather than disabling audience or nonce validation.

Reference: https://www.rfc-editor.org/rfc/rfc9901.html#section-4.3
