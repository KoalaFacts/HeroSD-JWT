# HeroSD-JWT

[![NuGet Version](https://img.shields.io/nuget/v/HeroSD-JWT.svg?style=flat-square&logo=nuget&label=NuGet)](https://www.nuget.org/packages/HeroSD-JWT/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/HeroSD-JWT.svg?style=flat-square&logo=nuget&label=Downloads)](https://www.nuget.org/packages/HeroSD-JWT/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/KoalaFacts/HeroSD-JWT/ci.yml?branch=main&style=flat-square&logo=github&label=Build)](https://github.com/KoalaFacts/HeroSD-JWT/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4?style=flat-square&logo=.net)](https://dotnet.microsoft.com/)
[![AOT Compatible](https://img.shields.io/badge/AOT-Compatible-blue?style=flat-square)](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/)

A .NET library implementing SD-JWT (Selective Disclosure for JSON Web Tokens) according to the IETF [draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) specification.

## Overview

SD-JWT enables privacy-preserving credential sharing by allowing holders to selectively disclose only necessary claims to verifiers, while cryptographically proving the disclosed claims are authentic and unmodified.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Simple API](#simple-api-recommended)
  - [Nested Object Disclosure](#nested-object-selective-disclosure)
  - [Array Element Disclosure](#array-element-selective-disclosure)
  - [Signature Algorithms](#different-signature-algorithms)
  - [Advanced API](#advanced-api-full-control)
- [Architecture](#architecture)
- [Security](#security)
- [Requirements](#requirements)
- [Native AOT and Trimming](#native-aot-and-trimming-compatibility)
- [Testing](#testing)
- [Performance](#performance)
- [Roadmap](#roadmap)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [References](#references)
- [Support](#support)

## Key Features
- Create SD-JWTs with selectively disclosable claims
- **Nested object selective disclosure** - Full support for nested properties like `address.street`, `address.geo.lat` (multi-level nesting)
- **Array element selective disclosure** - Syntax like `degrees[1]` for individual array elements
- **Array & Object Reconstruction API** - Automatically reconstruct hierarchical structures from disclosed claims
- **JWT Key Rotation Support** - RFC 7515 compliant `kid` parameter with key resolver pattern for secure key management
- **Key binding (proof of possession)** - RFC 7800 compliant with temporal validation
- **Decoy digests** - Privacy protection against claim enumeration
- Holder-controlled claim disclosure
- Cryptographic verification of signatures and claim integrity
- Zero third-party dependencies (uses only .NET BCL including `System.Security.Cryptography`, `System.Text.Json`, `System.Buffers.Text`)
- Constant-time comparison for security-critical operations
- Algorithm confusion prevention (rejects "none" algorithm)
- Multi-targeting .NET 8.0, .NET 9.0, and .NET 10.0

## Installation

```bash
dotnet add package HeroSD-JWT
```

Or via NuGet Package Manager:
```powershell
Install-Package HeroSD-JWT
```

## Quick Start

### Simple API (Recommended)

The fluent builder provides an easy, discoverable API:

```csharp
using HeroSdJwt.Issuance;
using HeroSdJwt.Common;
using HeroSdJwt.Core;

// Generate a signing key
var keyGen = KeyGenerator.Instance;
var key = keyGen.GenerateHmacKey();

// Create SD-JWT with fluent builder
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("name", "Alice")
    .WithClaim("email", "alice@example.com")
    .WithClaim("age", 30)
    .MakeSelective("email", "age")  // Selectively disclosable
    .SignWithHmac(key)
    .Build();

// Create presentation revealing only email
var presentation = sdJwt.ToPresentation("email");
```

### Nested Object Selective Disclosure

Selectively disclose nested properties with full JSONPath-style syntax:

```csharp
using HeroSdJwt.Cryptography;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Verification;

// Create SD-JWT with nested object claims
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-456")
    .WithClaim("address", new
    {
        street = "123 Main Street",
        city = "Boston",
        state = "MA",
        zip = "02101",
        geo = new { lat = 42.3601, lon = -71.0589 }
    })
    .MakeSelective("address.street", "address.city", "address.geo.lat", "address.geo.lon")
    .SignWithHmac(key)
    .Build();

// Holder creates presentation with only specific nested claims
var presentation = sdJwt.ToPresentation("address.street", "address.geo.lat");

// Verifier receives and verifies
var verifier = new SdJwtVerifier(
    new SdJwtVerificationOptions(),
    new EcPublicKeyConverter(),
    new SignatureValidator(),
    new DigestValidator(),
    new KeyBindingValidator(),
    new ClaimValidator());
var result = verifier.VerifyPresentation(presentation, key);

// Automatically reconstruct the nested object structure
var address = result.GetDisclosedObject("address");
// Returns: { "street": "123 Main Street", "geo": { "lat": 42.3601 } }
```

### Array Element Selective Disclosure

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("degrees", new[] { "BS", "MS", "PhD" })
    .MakeSelective("degrees[1]", "degrees[2]") // Only MS and PhD are selective
    .SignWithHmac(key)
    .Build();

// Create presentation
var presentation = sdJwt.ToPresentation("degrees[2]"); // Only reveal PhD

// Reconstruct array from disclosed elements
var result = verifier.VerifyPresentation(presentation, key);
var degrees = result.GetDisclosedArray("degrees");
// Returns: [null, null, "PhD"] - sparse array with only disclosed element
```

### Different Signature Algorithms

```csharp
var keyGen = KeyGenerator.Instance;

// HMAC (simple, symmetric)
var key = keyGen.GenerateHmacKey();
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email")
    .SignWithHmac(key)
    .Build();

// RSA (asymmetric, widely supported)
var (rsaPrivate, rsaPublic) = keyGen.GenerateRsaKeyPair();
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email")
    .SignWithRsa(rsaPrivate)
    .Build();

// ECDSA (asymmetric, compact)
var (ecPrivate, ecPublic) = keyGen.GenerateEcdsaKeyPair();
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email")
    .SignWithEcdsa(ecPrivate)
    .Build();
```

### JWT Key Rotation Support

HeroSD-JWT supports JWT key rotation using the `kid` (key ID) parameter per RFC 7515 Section 4.1.4. This enables secure key management practices including regular key rotation, emergency revocation, and multi-key deployments.

#### Issuing SD-JWTs with Key IDs

Add a key identifier when creating SD-JWTs:

```csharp
var keyGen = KeyGenerator.Instance;
var key = keyGen.GenerateHmacKey();

// Issue SD-JWT with key ID
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("email", "alice@example.com")
    .MakeSelective("email")
    .WithKeyId("key-2024-10")  // Add key identifier
    .SignWithHmac(key)
    .Build();
```

#### Verifying SD-JWTs with Key Resolver

Implement a key resolver to dynamically select verification keys based on the `kid` parameter:

```csharp
using HeroSdJwt.Cryptography;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

// Set up key resolver with multiple keys
var keys = new Dictionary<string, byte[]>
{
    ["key-2024-09"] = oldKey,
    ["key-2024-10"] = currentKey,
    ["key-2024-11"] = newKey
};

// Create resolver delegate
KeyResolver resolver = keyId => keys.GetValueOrDefault(keyId);

// Verify presentation using key resolver
var verifier = new SdJwtVerifier(
    new SdJwtVerificationOptions(),
    new EcPublicKeyConverter(),
    new SignatureValidator(),
    new DigestValidator(),
    new KeyBindingValidator(),
    new ClaimValidator());
var result = verifier.TryVerifyPresentation(presentation, resolver);

if (result.IsValid)
{
    // Access disclosed claims
    var email = result.DisclosedClaims["email"].GetString();
}
```

#### Key Rotation Workflow

Typical key rotation lifecycle (30-day overlap period):

```csharp
// Day 1-15: Only key-v1 active
var keysPhase1 = new Dictionary<string, byte[]>
{
    ["key-v1"] = keyV1
};

// Day 15-30: Both keys active (overlap period)
var keysPhase2 = new Dictionary<string, byte[]>
{
    ["key-v1"] = keyV1,  // Old key still valid
    ["key-v2"] = keyV2   // New key added
};
// Start issuing new tokens with key-v2, but both still verify

// Day 30+: Only key-v2 active (old key removed)
var keysPhase3 = new Dictionary<string, byte[]>
{
    ["key-v2"] = keyV2   // Only new key remains
};
// Old tokens with key-v1 now fail verification
```

#### Emergency Key Revocation

Immediately revoke a compromised key:

```csharp
// Before: Both keys active
var keys = new Dictionary<string, byte[]>
{
    ["compromised-key"] = compromisedKey,
    ["emergency-key"] = emergencyKey
};

// After: Immediately remove compromised key
keys.Remove("compromised-key");

// All tokens issued with compromised-key now fail verification immediately
KeyResolver resolver = keyId => keys.GetValueOrDefault(keyId);
```

#### Backward Compatibility

Tokens without `kid` parameter work seamlessly with a fallback key:

```csharp
// Verify tokens with or without kid
var result = verifier.TryVerifyPresentation(
    presentation,
    keyResolver: resolver,
    fallbackKey: legacyKey  // Used when JWT has no 'kid'
);
```

### Advanced API (Full Control)

For advanced scenarios, use the low-level API:

```csharp
using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;

var issuer = new SdJwtIssuer(
    new DisclosureGenerator(),
    new DigestCalculator(),
    new EcPublicKeyConverter(),
    new JwtSigner());
var claims = new Dictionary<string, object>
{
    ["sub"] = "user-123",
    ["email"] = "alice@example.com"
};

var signingKey = new byte[32];
var sdJwt = issuer.CreateSdJwt(
    claims,
    selectivelyDisclosableClaims: new[] { "email" },
    signingKey,
    HashAlgorithm.Sha256,
    SignatureAlgorithm.HS256);
```

**Array Element Example**:
```csharp
var claims = new Dictionary<string, object>
{
    ["sub"] = "user-456",
    ["degrees"] = new[] { "BS", "MS", "PhD" }
};

// Make only MS and PhD selectively disclosable, keep BS always visible
var sdJwt = issuer.CreateSdJwt(
    claims,
    selectivelyDisclosableClaims: new[] { "degrees[1]", "degrees[2]" },
    signingKey,
    HashAlgorithm.Sha256
);

// JWT payload will contain:
// "degrees": ["BS", {"...": "digest_for_MS"}, {"...": "digest_for_PhD"}]
```

**RS256/ES256 Example**:
```csharp
using System.Security.Cryptography;

// For RSA (RS256)
using var rsa = RSA.Create(2048);
var privateKey = rsa.ExportPkcs8PrivateKey();
var publicKey = rsa.ExportSubjectPublicKeyInfo();

var sdJwt = issuer.CreateSdJwt(
    claims,
    new[] { "email" },
    privateKey,
    HashAlgorithm.Sha256,
    SignatureAlgorithm.RS256);  // Specify algorithm

// For ECDSA (ES256)
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var privateKey = ecdsa.ExportPkcs8PrivateKey();
var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

var sdJwt = issuer.CreateSdJwt(
    claims,
    new[] { "email" },
    privateKey,
    HashAlgorithm.Sha256,
    SignatureAlgorithm.ES256);  // Specify algorithm
```

### 2. Holder: Create Presentation

```csharp
using HeroSdJwt.Presentation;

// Holder receives sdJwt from issuer and creates a presentation
var presenter = new SdJwtPresenter();

var presentation = presenter.CreatePresentation(
    sdJwt,
    claimsToDisclose: new[] { "birthdate" } // Only disclose birthdate
);

// Format for transmission
string presentationString = presentation.ToCombinedFormat();
// Format: "eyJhbGc...jwt...~WyI2cU1R...disclosure..."
```

### 3. Verifier: Verify Presentation

```csharp
using HeroSdJwt.Cryptography;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Verification;

// Parse presentation string
var parts = presentationString.Split('~');
var jwt = parts[0];
var disclosures = parts[1..^1]; // All parts between JWT and key binding

// Verify presentation
var verifier = new SdJwtVerifier(
    new SdJwtVerificationOptions(),
    new EcPublicKeyConverter(),
    new SignatureValidator(),
    new DigestValidator(),
    new KeyBindingValidator(),
    new ClaimValidator());
var verificationKey = new byte[32]; // Same key used for signing (HS256)

// Option 1: Throws exception on failure (recommended for most cases)
var result = verifier.VerifyPresentation(presentationString, verificationKey);
Console.WriteLine($"Birthdate: {result.DisclosedClaims["birthdate"]}");

// Option 2: Returns result without throwing (Try* pattern)
var result = verifier.TryVerifyPresentation(presentationString, verificationKey);
if (result.IsValid)
{
    Console.WriteLine("✅ Verification succeeded!");
    var birthdate = result.DisclosedClaims["birthdate"];
    Console.WriteLine($"Birthdate: {birthdate}");
}
else
{
    Console.WriteLine("❌ Verification failed!");
    foreach (var error in result.Errors)
    {
        Console.WriteLine($"Error: {error}");
    }
}
```

## Architecture

The library follows the three-party SD-JWT model:

```
┌─────────┐                  ┌────────┐                  ┌──────────┐
│ Issuer  │                  │ Holder │                  │ Verifier │
└────┬────┘                  └────┬───┘                  └────┬─────┘
     │                            │                           │
     │  1. Create SD-JWT          │                           │
     │  with selective disclosures│                           │
     │───────────────────────────>│                           │
     │                            │                           │
     │                            │  2. Select claims         │
     │                            │  to disclose              │
     │                            │                           │
     │                            │  3. Create presentation   │
     │                            │──────────────────────────>│
     │                            │                           │
     │                            │                           │  4. Verify
     │                            │                           │  signature
     │                            │                           │  & digests
     │                            │                           │
```

## Security

This library implements security best practices:

- **Constant-time comparison**: Uses `CryptographicOperations.FixedTimeEquals` for digest validation to prevent timing attacks
- **Algorithm confusion prevention**: Rejects "none" algorithm (both lowercase and uppercase)
- **Cryptographically secure salts**: Uses `RandomNumberGenerator` for 128-bit salts
- **No third-party dependencies**: Zero supply chain risk from third-party packages (uses only .NET BCL)
- **Strict validation**: Treats warnings as errors, validates all inputs

### Supported Algorithms

- **Hash algorithms**: SHA-256 (default), SHA-384, SHA-512
- **Signature algorithms**:
  - **HS256** (HMAC-SHA256) - Symmetric signing with HMAC
  - **RS256** (RSA-SHA256) - Asymmetric signing with RSA (minimum 2048 bits)
  - **ES256** (ECDSA-P256-SHA256) - Asymmetric signing with ECDSA (P-256 curve)

### Security Policy

For vulnerability reporting and security best practices, see:
- **[SECURITY.md](SECURITY.md)** - Vulnerability disclosure policy and security contact
- **[Security Guide](docs/users/security.md)** - Detailed security best practices and guidelines

## Requirements

- **.NET 8.0** (LTS), **.NET 9.0**, or **.NET 10.0**
- No third-party dependencies (uses only .NET BCL)
  - Note: .NET 8.0 includes a polyfill dependency (`Microsoft.Bcl.Memory`) to backport .NET 9.0+'s native `Base64Url` APIs

## Native AOT and Trimming Compatibility

**AOT-Compatible with Standard JSON Types**: This library works with .NET Native AOT compilation when used with standard JSON-serializable types.

**Implementation approach**:
- Uses `Utf8JsonWriter` for all **internal** JSON serialization (disclosures, JWTs, key binding)
- Direct dictionary parsing for JWK handling (no serialize-then-deserialize round-trips)
- All cryptographic operations use standard BCL APIs
- Minimal reflection usage - only at API boundary for user-provided claim values

**API Boundary Consideration**:
The public API accepts `Dictionary<string, object>` for claim values to support any JSON-serializable type. This means:
- **Primitive types work in AOT**: string, int, long, double, bool, arrays, dictionaries
- **JsonElement works perfectly in AOT**: Pre-parsed JSON values
- **Custom classes may require trimming annotations**: If you pass custom POCOs, ensure they're preserved

**Key technical details**:
- SD-JWT disclosure arrays use `Utf8JsonWriter`: `[salt, claim_name, claim_value]`
- Internal processing is fully AOT-compatible (no reflection beyond JSON serialization)
- JWT headers and payloads serialized with explicit type handling

**Recommendation for AOT applications**:
```csharp
// Instead of custom classes:
var claims = new Dictionary<string, object>
{
    ["sub"] = "user-123",
    ["email"] = "alice@example.com",
    ["age"] = 30
};

// Or use JsonElement for pre-parsed JSON:
var claims = new Dictionary<string, object>
{
    ["sub"] = "user-123",
    ["profile"] = JsonSerializer.SerializeToElement(new { name = "Alice", age = 30 })
};
```

## Testing

```bash
# Run all tests
dotnet test

# Run with verbose output
dotnet test --verbosity normal
```

## Performance

- **Verification**: < 100ms for 50-claim SD-JWTs
- **Processing**: < 500ms for 100-claim SD-JWTs
- **Thread-agnostic design**: Reuse `SdJwtIssuer`, `SdJwtPresenter`, `SdJwtVerifier` instances (you handle synchronization)

## Documentation

Comprehensive documentation is available in the [docs/](docs/) directory:

- **[Getting Started Guide](docs/users/getting-started.md)** - Installation and first steps
- **[Examples](docs/users/examples.md)** - Detailed code examples for various scenarios
- **[Security Best Practices](docs/users/security.md)** - Important security considerations
- **[API Reference](docs/users/api-reference.md)** - Complete API documentation

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

Quick overview:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests first (TDD)
4. Ensure all tests pass (`dotnet test`)
5. Follow .NET naming conventions
6. Add XML documentation for public APIs
7. Commit your changes (`git commit -m 'feat: add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details on code style, testing, and the review process.

## License

MIT License - see [LICENSE](LICENSE) file for details

## References

- **Specification**: [IETF draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- **Repository**: https://github.com/KoalaFacts/HeroSD-JWT
- **NuGet Package**: https://www.nuget.org/packages/HeroSD-JWT
- **RFC 7800**: [Proof-of-Possession Key Semantics for JWTs](https://www.rfc-editor.org/rfc/rfc7800.html)

## Support

- **Issues**: Report bugs at https://github.com/KoalaFacts/HeroSD-JWT/issues
- **Discussions**: Community support via GitHub Discussions
