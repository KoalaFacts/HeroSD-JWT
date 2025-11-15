# Builder Pattern API

HeroSD-JWT provides fluent builder APIs for both token issuance and verification, making the library easy to use and discover.

## SdJwtBuilder (Issuance)

Create and sign SD-JWTs with a clean, fluent API:

```csharp
using HeroSdJwt.Issuance;

// Simple HMAC signing
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user@example.com")
    .WithClaim("email", "user@example.com")
    .WithClaim("age", 30)
    .MakeSelective("email", "age")
    .SignWithHmac(hmacKey)
    .Build();

// RSA signing with key binding and decoys
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email", "phone", "address")
    .SignWithRsa(rsaPrivateKey)
    .WithKeyBinding(holderPublicKey)
    .WithDecoys(5)
    .WithKeyId("key-2024-11")
    .Build();

// EC signing (EdDSA)
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "alice@example.com")
    .WithClaim("jti", Guid.NewGuid().ToString())
    .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
    .SignWithEdDsa(ed25519PrivateKey)
    .Build();
```

## SdJwtVerifierBuilder (Verification)

Configure verifiers with revocation, replay protection, and validation rules:

### Basic Usage

```csharp
using HeroSdJwt.Verification;

// Simple case - defaults only
var verifier = SdJwtVerifierBuilder.Create()
    .Build();

var result = verifier.TryVerifyPresentation(presentation, publicKey);
if (result.IsValid)
{
    Console.WriteLine($"Subject: {result.Claims["sub"]}");
}
```

### With Revocation Support

```csharp
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;

// Create revocation store
var revocationStore = new InMemoryRevocationStore();

// Configure verifier with revocation
var verifier = SdJwtVerifierBuilder.Create()
    .WithRevocation(revocationStore)
    .WithFailClosed()  // Secure default: reject if revocation check fails
    .Build();

// Verify token
var result = verifier.TryVerifyPresentation(presentation, publicKey);

// Revoke a token
await revocationStore.RevokeJtiAsync(
    jti: "token-abc-123",
    expiration: DateTimeOffset.UtcNow.AddHours(1),
    cancellationToken);

// Future verifications of this token will fail
```

### With Replay Protection

```csharp
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;

// Create JTI cache and validator
var cache = new InMemoryJtiCache(new ReplayProtectionOptions
{
    Enabled = true,
    RequireJtiClaim = true,
    SlidingExpirationWindow = TimeSpan.FromMinutes(15)
});

var jtiValidator = new JtiValidator(cache, new ReplayProtectionOptions
{
    Enabled = true,
    RequireJtiClaim = true
});

// Configure verifier
var verifier = SdJwtVerifierBuilder.Create()
    .WithReplayProtection(jtiValidator)
    .Build();

// First verification succeeds
var result1 = verifier.VerifyPresentation(presentation, publicKey);

// Second verification with same token fails (replay attack detected)
// Throws ReplayAttackException
```

### Full Configuration

```csharp
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;
using HeroSdJwt.Verification.ReplayProtection;
using HeroSdJwt.Primitives;

var revocationStore = new InMemoryRevocationStore();
var jtiValidator = CreateJtiValidator(); // Your replay protection setup

var verifier = SdJwtVerifierBuilder.Create()
    // Validation rules
    .WithExpectedIssuer("https://issuer.example.com")
    .WithExpectedAudience("https://api.example.com")
    .WithExpectedHashAlgorithm(HashAlgorithm.Sha256)
    .WithExpectedNonce("challenge-nonce-123")
    .WithClockSkew(TimeSpan.FromMinutes(2))

    // Security features
    .RequireKeyBinding()
    .WithRevocation(revocationStore, RevocationFailureMode.FailClosed)
    .WithReplayProtection(jtiValidator)

    .Build();
```

## Revocation Scenarios

### 1. User Logout (JTI Revocation)

```csharp
// User logs out - revoke specific token
var jti = "session-token-xyz";
await revocationStore.RevokeJtiAsync(
    jti,
    expiration: DateTimeOffset.UtcNow.AddHours(24),
    cancellationToken);

// Token is now revoked
var result = verifier.TryVerifyPresentation(presentation, publicKey);
Assert.False(result.IsValid);
Assert.Contains(ErrorCode.TokenRevoked, result.Errors);
```

### 2. Compromised Signing Key (Key ID Revocation)

```csharp
// Signing key compromised - revoke ALL tokens from that key
await revocationStore.RevokeKeyAsync("key-2024-10", cancellationToken);

// All tokens signed with "key-2024-10" are now revoked
var result = verifier.TryVerifyPresentation(presentation, publicKey);
Assert.False(result.IsValid);
Assert.Contains(ErrorCode.TokenRevokedByKey, result.Errors);
```

### 3. Emergency Lockdown (User Revocation)

```csharp
// Suspicious activity - revoke ALL tokens for user
var userId = "alice@example.com";
await revocationStore.RevokeUserAsync(userId, cancellationToken);

// All tokens for alice@example.com are now revoked
var result = verifier.TryVerifyPresentation(presentation, publicKey);
Assert.False(result.IsValid);
Assert.Contains(ErrorCode.TokenRevokedByUser, result.Errors);

// Later: incident resolved - restore access
await revocationStore.UnrevokeUserAsync(userId, cancellationToken);
```

## Failure Modes

### Fail-Closed (Secure Default)

```csharp
var verifier = SdJwtVerifierBuilder.Create()
    .WithRevocation(revocationStore)
    .WithFailClosed()  // If revocation check fails, reject token
    .Build();

// If database is down, tokens are rejected (secure)
// Prioritizes security over availability
```

### Fail-Open (High Availability)

```csharp
var verifier = SdJwtVerifierBuilder.Create()
    .WithRevocation(revocationStore)
    .WithFailOpen()  // If revocation check fails, allow token
    .Build();

// If database is down, tokens are still accepted (less secure)
// Prioritizes availability over security
// WARNING: Use only if absolutely necessary
```

## Testing with Custom Dependencies

```csharp
// For testing, you can inject custom validators
var verifier = SdJwtVerifierBuilder.Create()
    .WithSignatureValidator(mockSignatureValidator)
    .WithDigestValidator(mockDigestValidator)
    .WithKeyBindingValidator(mockKeyBindingValidator)
    .WithClaimValidator(mockClaimValidator)
    .WithEcPublicKeyConverter(mockEcConverter)
    .Build();
```

## Migration from Constructor-Based API

### Before (Constructor DI)

```csharp
var verifier = new SdJwtVerifier(
    new SdJwtVerificationOptions
    {
        ExpectedIssuer = "https://issuer.example.com",
        ClockSkew = TimeSpan.FromMinutes(2),
        Revocation = new RevocationOptions
        {
            FailureMode = RevocationFailureMode.FailClosed
        }
    },
    new EcPublicKeyConverter(),
    new SignatureValidator(),
    new DigestValidator(),
    new KeyBindingValidator(),
    new ClaimValidator(),
    jtiValidator: null,
    revocationStore: revocationStore);
```

### After (Builder Pattern)

```csharp
var verifier = SdJwtVerifierBuilder.Create()
    .WithExpectedIssuer("https://issuer.example.com")
    .WithClockSkew(TimeSpan.FromMinutes(2))
    .WithRevocation(revocationStore, RevocationFailureMode.FailClosed)
    .Build();
```

Much cleaner! 🎉

## Best Practices

1. **Use builders for application code** - More discoverable and maintainable
2. **Use constructor DI for library integration** - When integrating with DI containers
3. **Store verifiers as singletons** - They're thread-safe and expensive to create
4. **Use fail-closed for security-critical apps** - Reject tokens if revocation check fails
5. **Use fail-open only when necessary** - High availability requirements only

## See Also

- [Getting Started](getting-started.md)
- [Security Features](security.md)
- [Examples](examples.md)
