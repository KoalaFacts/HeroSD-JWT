# HeroSD-JWT

A .NET library implementing SD-JWT (Selective Disclosure for JSON Web Tokens) according to the IETF [draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) specification.

## Overview

SD-JWT enables privacy-preserving credential sharing by allowing holders to selectively disclose only necessary claims to verifiers, while cryptographically proving the disclosed claims are authentic and unmodified.

**Key Features**:
- ✅ Create SD-JWTs with selectively disclosable claims
- ✅ **Nested object selective disclosure** - Full support for nested properties like `address.street`, `address.geo.lat` (multi-level nesting)
- ✅ **Array element selective disclosure** - Syntax like `degrees[1]` for individual array elements
- ✅ **Array & Object Reconstruction API** - Automatically reconstruct hierarchical structures from disclosed claims
- ✅ **Key binding (proof of possession)** - RFC 7800 compliant with temporal validation
- ✅ **Decoy digests** - Privacy protection against claim enumeration
- ✅ Holder-controlled claim disclosure
- ✅ Cryptographic verification of signatures and claim integrity
- ✅ Zero third-party dependencies (uses only .NET BCL including `System.Security.Cryptography`, `System.Text.Json`, `System.Buffers.Text`)
- ✅ Constant-time comparison for security-critical operations
- ✅ Algorithm confusion prevention (rejects "none" algorithm)
- ✅ Multi-targeting .NET 8.0 and .NET 9.0

## Installation

```bash
dotnet add package HeroSD-JWT
```

Or via NuGet Package Manager:
```powershell
Install-Package HeroSD-JWT
```

## Quick Start

### ✨ Simple API (Recommended)

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

### 🏢 Nested Object Selective Disclosure

Selectively disclose nested properties with full JSONPath-style syntax:

```csharp
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
var verifier = new SdJwtVerifier();
var result = verifier.VerifyPresentation(presentation, key);

// Automatically reconstruct the nested object structure
var address = result.GetDisclosedObject("address");
// Returns: { "street": "123 Main Street", "geo": { "lat": 42.3601 } }
```

### 📊 Array Element Selective Disclosure

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

### 🔑 Different Signature Algorithms

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

### 🔧 Advanced API (Full Control)

For advanced scenarios, use the low-level API:

```csharp
using HeroSdJwt.Issuance;
using HeroSdJwt.Common;

var issuer = new SdJwtIssuer();
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
using HeroSdJwt.Verification;

// Parse presentation string
var parts = presentationString.Split('~');
var jwt = parts[0];
var disclosures = parts[1..^1]; // All parts between JWT and key binding

// Verify presentation
var verifier = new SdJwtVerifier();
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

## Project Structure

```
src/
├── Core/               # Domain models (SdJwt, Disclosure, Digest, VerificationResult)
├── Common/             # Shared utilities (HashAlgorithm, ErrorCodes, Base64UrlEncoder)
├── Issuance/           # SD-JWT creation (SdJwtIssuer, DisclosureGenerator, DigestCalculator)
├── Presentation/       # Claim selection & formatting (SdJwtPresenter, SdJwtPresentation)
└── Verification/       # Signature & digest validation (SdJwtVerifier, SignatureValidator, DigestValidator)

tests/
├── Contract/           # Public API contract tests
├── Unit/               # Unit tests for individual components
└── Security/           # Security-specific tests (timing attacks, algorithm confusion, salt entropy)
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

## Requirements

- **.NET 8.0** (LTS) or **.NET 9.0**
- No third-party dependencies (uses only .NET BCL)
  - Note: .NET 8.0 includes a polyfill dependency (`Microsoft.Bcl.Memory`) to backport .NET 9.0's native `Base64Url` APIs

## Testing

```bash
# Run all tests
dotnet test

# Run with verbose output
dotnet test --verbosity normal
```

Current test coverage: **277 passing tests** across:
- Contract tests (API behavior)
- Unit tests (component logic, array elements, claim paths, disclosures, signature algorithms, Base64Url encoding, decoy digests, JWK handling, builder API, crypto helpers)
- Integration tests (end-to-end flows with arrays and nested claims)
- Security tests (timing attacks, algorithm confusion, salt entropy, key binding)

## Performance

- **Verification**: < 100ms for 50-claim SD-JWTs
- **Processing**: < 500ms for 100-claim SD-JWTs
- **Thread-agnostic design**: Reuse `SdJwtIssuer`, `SdJwtPresenter`, `SdJwtVerifier` instances (you handle synchronization)

## Roadmap

### ✅ Completed
- [x] **Key binding (proof of possession)** - RFC 7800 compliant with temporal validation
- [x] **Array element selective disclosure** - Full support with syntax like `degrees[1]`
- [x] **Decoy digests for privacy enhancement** - Cryptographically secure decoy generation
- [x] **Security hardening** - Critical claim protection, _sd_alg placement validation, KB-JWT replay prevention
- [x] **Integration tests for end-to-end flows** - 7 comprehensive tests
- [x] **Nested property path parsing** - Foundation with dot notation support (`address.street`)
- [x] **Nested claims selective disclosure** - Full support for nested properties with `_sd` arrays
- [x] **RS256/ES256 signature algorithm support** - All three algorithms (HS256, RS256, ES256) fully implemented

### 🚧 In Progress / Planned
- [ ] **Performance benchmarks** - Systematic benchmarking suite
- [ ] **NuGet package publishing** - Production-ready release

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Write tests first (TDD)
2. Ensure all tests pass
3. Follow .NET naming conventions
4. Add XML documentation for public APIs
5. No third-party dependencies (BCL only)

## License

MIT License - see [LICENSE](LICENSE) file for details

## References

- **Specification**: [IETF draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- **Repository**: https://github.com/KoalaFacts/HeroSD-JWT
- **Quick Start**: See [specs/001-sd-jwt-library/quickstart.md](specs/001-sd-jwt-library/quickstart.md)
- **Implementation Plan**: See [specs/001-sd-jwt-library/plan.md](specs/001-sd-jwt-library/plan.md)

## Support

- **Issues**: Report bugs at https://github.com/KoalaFacts/HeroSD-JWT/issues
- **Discussions**: Community support via GitHub Discussions

---

**Status**: ✅ Production Ready - All features complete

**Version**: 1.0.0 (stable release)
