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

Implement key rotation to limit the impact of key compromise. HeroSD-JWT supports the `kid` (key ID) parameter per RFC 7515 for enterprise-grade key rotation:

#### Basic Key Rotation Strategy

1. **Deploy new key** (pre-deployment phase)
2. **Activate new key** for issuing new tokens
3. **Maintain old keys** for verification during overlap period
4. **Remove old keys** after retention period

#### Using Key IDs

Issue SD-JWTs with key identifiers:

```csharp
using HeroSdJwt.Issuance;

var keyGen = KeyGenerator.Instance;
var key = keyGen.GenerateHmacKey();

// Issue with key ID
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("email", "alice@example.com")
    .MakeSelective("email")
    .WithKeyId("key-2024-11")  // RFC 7515 kid parameter
    .SignWithHmac(key)
    .Build();
```

#### Key Resolver Pattern

Implement dynamic key resolution for multi-key deployments:

```csharp
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

// Set up key store
var keyStore = new Dictionary<string, byte[]>
{
    ["key-2024-10"] = previousKey,
    ["key-2024-11"] = currentKey,
    ["key-2024-12"] = nextKey  // Pre-deployed
};

// Create resolver
KeyResolver resolver = keyId => keyStore.GetValueOrDefault(keyId);

// Verify with resolver
var verifier = new SdJwtVerifier();
var result = verifier.TryVerifyPresentation(presentation, resolver);

if (!result.IsValid)
{
    Console.WriteLine($"Verification failed: {result.ErrorMessage}");
}
```

#### Production Key Rotation Service

Complete production-ready implementation:

```csharp
public class ProductionKeyRotationService
{
    private readonly Dictionary<string, KeyMetadata> _keys = new();
    private readonly ILogger _logger;

    public class KeyMetadata
    {
        public byte[] Key { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? RotatedAt { get; set; }
        public DateTime? DeactivatedAt { get; set; }
        public bool IsActive { get; set; }
        public string Algorithm { get; set; } = "HS256";
    }

    public string IssueToken(Dictionary<string, object> claims, string[] selectiveClaims)
    {
        var activeKey = _keys.FirstOrDefault(k => k.Value.IsActive);
        if (activeKey.Key == null)
            throw new InvalidOperationException("No active signing key available");

        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .MakeSelective(selectiveClaims)
            .WithKeyId(activeKey.Key)
            .SignWithHmac(activeKey.Value.Key)
            .Build();

        _logger.LogInformation("Issued token with key: {KeyId}", activeKey.Key);
        return sdJwt.EncodedSdJwt;
    }

    public void DeployNewKey()
    {
        var keyGen = KeyGenerator.Instance;
        var newKeyId = $"key-{DateTime.UtcNow:yyyy-MM-dd-HHmmss}";
        var newKey = keyGen.GenerateHmacKey();

        _keys[newKeyId] = new KeyMetadata
        {
            Key = newKey,
            CreatedAt = DateTime.UtcNow,
            IsActive = false
        };

        _logger.LogInformation("Deployed new key: {KeyId}", newKeyId);
    }

    public void ActivateKey(string keyId)
    {
        if (!_keys.ContainsKey(keyId))
            throw new ArgumentException($"Key not found: {keyId}");

        // Deactivate current key
        foreach (var key in _keys.Where(k => k.Value.IsActive))
        {
            key.Value.IsActive = false;
            key.Value.RotatedAt = DateTime.UtcNow;
            _logger.LogInformation("Rotated key: {KeyId}", key.Key);
        }

        // Activate new key
        _keys[keyId].IsActive = true;
        _logger.LogInformation("Activated key: {KeyId}", keyId);
    }

    public void RemoveOldKeys(TimeSpan retentionPeriod)
    {
        var cutoff = DateTime.UtcNow - retentionPeriod;
        var oldKeys = _keys
            .Where(k => k.Value.RotatedAt.HasValue && k.Value.RotatedAt < cutoff)
            .Select(k => k.Key)
            .ToList();

        foreach (var keyId in oldKeys)
        {
            _keys.Remove(keyId);
            _logger.LogWarning("Removed old key: {KeyId}", keyId);
        }
    }

    public KeyResolver GetKeyResolver()
    {
        return keyId =>
        {
            if (_keys.TryGetValue(keyId, out var metadata))
            {
                return metadata.Key;
            }

            _logger.LogError("Unknown key ID requested: {KeyId}", keyId);
            return null;
        };
    }

    public void MonitorKeyHealth()
    {
        foreach (var key in _keys)
        {
            var age = DateTime.UtcNow - key.Value.CreatedAt;
            if (age > TimeSpan.FromDays(90) && key.Value.IsActive)
            {
                _logger.LogWarning(
                    "Active key {KeyId} is {Days} days old - consider rotation",
                    key.Key,
                    age.Days);
            }
        }
    }
}
```

#### Key Rotation Best Practices

1. **Rotation Schedule**
   - Rotate keys every 90 days minimum
   - Immediately rotate if compromise is suspected
   - Document rotation procedures

2. **Overlap Period**
   - Deploy new key 24-48 hours before activation
   - Keep old keys for verification during transition
   - Typical overlap: 7-30 days depending on token lifetime

3. **Key Retention**
   - Retain deactivated keys for token lifetime + grace period
   - For 30-day tokens, keep old keys for 60 days minimum
   - Archive old keys securely before deletion

4. **Monitoring**
   - Track key usage metrics
   - Alert on unknown key IDs
   - Monitor key age and rotation compliance
   - Log all key lifecycle events

5. **Emergency Rotation**
   ```csharp
   public void EmergencyKeyRotation()
   {
       // 1. Deploy new key immediately
       DeployNewKey();

       // 2. Activate immediately (no overlap period)
       var newKeyId = _keys.OrderByDescending(k => k.Value.CreatedAt)
                          .First().Key;
       ActivateKey(newKeyId);

       // 3. Revoke compromised keys
       foreach (var key in _keys.Where(k => !k.Value.IsActive))
       {
           key.Value.DeactivatedAt = DateTime.UtcNow;
       }

       // 4. Alert monitoring systems
       _logger.LogCritical("EMERGENCY: Key rotation completed");
   }
   ```

6. **Key ID Naming**
   - Use descriptive, sortable key IDs
   - Include timestamp: `key-2024-11-14`
   - Include environment: `key-prod-2024-11`
   - Max length: 256 characters
   - Use printable ASCII only

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
