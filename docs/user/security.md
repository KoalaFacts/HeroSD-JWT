# Security Best Practices

This document outlines security considerations and best practices when using HeroSD-JWT.

## Table of Contents

- [Overview](#overview)
- [Built-in Security Features](#built-in-security-features)
- [Key Management](#key-management)
- [Algorithm Selection](#algorithm-selection)
- [Key Binding](#key-binding)
- [Critical Claims](#critical-claims)
- [Privacy Considerations](#privacy-considerations)
- [Common Pitfalls](#common-pitfalls)
- [Security Testing](#security-testing)

## Overview

HeroSD-JWT implements multiple security layers to protect against common attacks and vulnerabilities. However, proper usage is essential for maintaining security in your application.

## Built-in Security Features

### Constant-Time Comparison

HeroSD-JWT uses `CryptographicOperations.FixedTimeEquals` for all digest comparisons to prevent timing attacks:

```csharp
// ✅ Good - Protected against timing attacks
var result = verifier.VerifyPresentation(presentation, key);
```

The library automatically uses constant-time comparison internally. You don't need to do anything special.

### Algorithm Confusion Prevention

The library rejects the "none" algorithm to prevent algorithm confusion attacks:

```csharp
// ❌ This will throw an exception
var jwt = "eyJhbGciOiJub25lIn0...";  // "none" algorithm
var result = verifier.VerifyPresentation(jwt, key);  // Throws!
```

### Cryptographically Secure Salt Generation

All salts are generated using `RandomNumberGenerator` with a minimum of 128 bits:

```csharp
// ✅ Library automatically generates secure salts
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("email", "alice@example.com")
    .MakeSelective("email")  // Secure salt generated internally
    .SignWithHmac(key)
    .Build();
```

### Critical Claim Protection

Critical JWT claims cannot be made selectively disclosable:

```csharp
// ❌ This will throw an exception
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("iss", "https://issuer.example.com")
    .MakeSelective("iss")  // Error! "iss" is a critical claim
    .Build();
```

Protected claims: `iss`, `aud`, `exp`, `nbf`, `iat`, `cnf`, `_sd_alg`

## Key Management

### Generating Keys

Always use the `KeyGenerator` for cryptographically secure key generation:

```csharp
var keyGen = KeyGenerator.Instance;

// ✅ HMAC key (256 bits)
var hmacKey = keyGen.GenerateHmacKey();

// ✅ RSA key pair (2048 bits minimum)
var (rsaPrivate, rsaPublic) = keyGen.GenerateRsaKeyPair();

// ✅ ECDSA key pair (P-256 curve)
var (ecPrivate, ecPublic) = keyGen.GenerateEcdsaKeyPair();
```

### Storing Keys Securely

**Never hardcode keys in your source code!**

```csharp
// ❌ BAD - Keys in source code
var key = new byte[] { 0x01, 0x02, 0x03, ... };

// ✅ GOOD - Keys from secure storage
var key = await keyVault.GetSecretAsync("sd-jwt-signing-key");
```

Best practices:
- Use Azure Key Vault, AWS KMS, or similar secure key storage
- Rotate keys regularly
- Use different keys for different purposes
- Never commit keys to version control

### Key Rotation

Implement key rotation to limit the impact of key compromise:

```csharp
public class KeyRotationService
{
    private readonly Dictionary<string, byte[]> _keys = new();

    public byte[] GetCurrentKey() => _keys["current"];

    public byte[] GetKeyById(string keyId) => _keys[keyId];

    public void RotateKeys()
    {
        _keys["previous"] = _keys["current"];
        _keys["current"] = KeyGenerator.Instance.GenerateHmacKey();
    }
}
```

## Algorithm Selection

### HMAC (HS256)

**Use when:** Both parties share a secret key (symmetric)

**Pros:**
- Fast
- Simple key management
- Smaller signatures

**Cons:**
- Both issuer and verifier have the same key
- Key must be transmitted securely

```csharp
// Good for internal systems where both parties trust each other
var key = keyGen.GenerateHmacKey();
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .SignWithHmac(key)
    .Build();
```

### RSA (RS256)

**Use when:** Public key cryptography is needed

**Pros:**
- Public key can be shared openly
- Widely supported
- Good for cross-organization scenarios

**Cons:**
- Slower than HMAC
- Larger keys and signatures
- More complex key management

```csharp
// Good for scenarios where verifiers don't need the private key
var (privateKey, publicKey) = keyGen.GenerateRsaKeyPair();
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .SignWithRsa(privateKey)
    .Build();

// Public key can be shared with verifiers
```

**Security note:** Always use at least 2048-bit keys. HeroSD-JWT enforces this minimum.

### ECDSA (ES256)

**Use when:** Public key cryptography with smaller keys is needed

**Pros:**
- Smaller keys and signatures than RSA
- Fast
- Modern cryptography

**Cons:**
- Less widely supported than RSA
- More complex implementation

```csharp
// Good for resource-constrained environments or mobile apps
var (privateKey, publicKey) = keyGen.GenerateEcdsaKeyPair();
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .SignWithEcdsa(privateKey)
    .Build();
```

**Recommended:** ES256 is the recommended choice for new applications due to its balance of security and efficiency.

## Key Binding

Key binding (proof of possession) prevents presentation theft. Always use it when the holder's identity is critical:

```csharp
// ✅ With key binding - Secure
var holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var holderPublicKey = holderKey.ExportSubjectPublicKeyInfo();

// Issuer binds SD-JWT to holder's key
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithHolderPublicKey(holderPublicKey, "ES256")
    .SignWithHmac(issuerKey)
    .Build();

// Holder must prove possession
var holderPrivateKey = holderKey.ExportPkcs8PrivateKey();
var presentation = sdJwt.ToPresentationWithKeyBinding(
    holderPrivateKey,
    SignatureAlgorithm.ES256,
    audience: "https://verifier.example.com",
    nonce: "random-nonce",
    claimsToDisclose: new[] { "email" }
);
```

### Temporal Validation

Always validate `iat` (issued at) in key binding JWTs:

```csharp
var result = verifier.VerifyPresentation(
    presentation,
    issuerKey,
    expectedAudience: "https://verifier.example.com",
    expectedNonce: "random-nonce"
);

// Library automatically validates iat (must be recent)
```

### Replay Prevention

Use unique nonces for each verification request:

```csharp
// ✅ Good - Unique nonce per request
var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

// ❌ Bad - Reusing nonces
var nonce = "constant-nonce";  // Don't do this!
```

## Critical Claims

Never make these claims selectively disclosable:

- `iss` (issuer) - Identity of the issuer
- `aud` (audience) - Intended recipient
- `exp` (expiration) - When the token expires
- `nbf` (not before) - When the token becomes valid
- `iat` (issued at) - When the token was issued
- `cnf` (confirmation) - Key binding information
- `_sd_alg` (hash algorithm) - Prevents algorithm substitution

```csharp
// ✅ Good - Critical claims are always visible
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("iss", "https://issuer.example.com")
    .WithClaim("sub", "user-123")
    .WithClaim("email", "alice@example.com")
    .MakeSelective("email")  // Only non-critical claims
    .SignWithHmac(key)
    .Build();
```

## Privacy Considerations

### Decoy Digests

Use decoy digests to prevent claim enumeration:

```csharp
// Add decoy digests to hide the number of selective claims
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("email", "alice@example.com")
    .WithClaim("phone", "+1-555-0100")
    .MakeSelective("email", "phone")
    .WithDecoys(3)  // Add 3 decoy digests
    .SignWithHmac(key)
    .Build();
```

**Without decoys:** Verifier knows exactly how many selective claims exist
**With decoys:** Verifier cannot determine the true number of selective claims

### Minimal Disclosure

Always disclose the minimum information necessary:

```csharp
// ❌ Over-disclosure
var presentation = sdJwt.ToPresentationWithAllClaims();

// ✅ Minimal disclosure
var presentation = sdJwt.ToPresentation("birthdate");  // Only what's needed
```

### Nested Claims for Granular Control

Use nested objects for fine-grained disclosure:

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("address", new
    {
        street = "123 Main St",
        city = "Boston",
        state = "MA",
        zip = "02101"
    })
    .MakeSelective(
        "address.street",  // Can disclose street separately
        "address.zip"      // Can disclose zip separately
    )
    .SignWithHmac(key)
    .Build();

// Disclose only city and state (not street or zip)
var presentation = sdJwt.ToPresentation();  // No selective claims
```

## Common Pitfalls

### 1. Using Weak Keys

```csharp
// ❌ BAD - Weak key
var key = new byte[16];  // Only 128 bits

// ✅ GOOD - Strong key
var key = keyGen.GenerateHmacKey();  // 256 bits
```

### 2. Not Validating Audience

```csharp
// ❌ BAD - No audience validation
var result = verifier.VerifyPresentation(presentation, key);

// ✅ GOOD - Validate audience
var result = verifier.VerifyPresentation(
    presentation,
    key,
    expectedAudience: "https://my-service.example.com"
);
```

### 3. Ignoring Expiration

```csharp
// ❌ BAD - No expiration check
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .SignWithHmac(key)
    .Build();

// ✅ GOOD - Include expiration
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
    .SignWithHmac(key)
    .Build();

// Verifier should validate expiration
if (result.DisclosedClaims.TryGetValue("exp", out var exp))
{
    var expiration = DateTimeOffset.FromUnixTimeSeconds((long)exp);
    if (expiration < DateTimeOffset.UtcNow)
    {
        throw new InvalidOperationException("Token expired");
    }
}
```

### 4. Trusting Unverified Claims

```csharp
// ❌ BAD - Using claims before verification
var claims = ParsePresentation(presentation);
var email = claims["email"];  // DANGER!

// ✅ GOOD - Verify first
var result = verifier.VerifyPresentation(presentation, key);
var email = result.DisclosedClaims["email"];  // Safe
```

## Security Testing

HeroSD-JWT includes comprehensive security tests. Run them regularly:

```bash
# Run all tests including security tests
dotnet test

# Run only security tests
dotnet test --filter Category=Security
```

Security test categories:
- Timing attack resistance
- Algorithm confusion prevention
- Salt entropy validation
- Key binding temporal validation
- Replay attack prevention

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do NOT** open a public issue
2. Email security concerns to the maintainers
3. Include a detailed description and reproduction steps
4. Allow time for a fix before public disclosure

## Additional Resources

- [IETF SD-JWT Specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- [RFC 7800: Proof-of-Possession Key Semantics](https://www.rfc-editor.org/rfc/rfc7800.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
