# HeroSD-JWT

[![NuGet Version](https://img.shields.io/nuget/v/HeroSD-JWT.svg?style=flat-square&logo=nuget&label=NuGet)](https://www.nuget.org/packages/HeroSD-JWT/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/HeroSD-JWT.svg?style=flat-square&logo=nuget&label=Downloads)](https://www.nuget.org/packages/HeroSD-JWT/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/KoalaFacts/HeroSD-JWT/ci.yml?branch=main&style=flat-square&logo=github&label=Build)](https://github.com/KoalaFacts/HeroSD-JWT/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4?style=flat-square&logo=.net)](https://dotnet.microsoft.com/)
[![Native AOT requires validation](https://img.shields.io/badge/Native%20AOT-verify%20per%20path-blue?style=flat-square)](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/)

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
- [Development](#development)
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
- Uses .NET BCL APIs plus `Microsoft.Bcl.Memory` on .NET 8; Ed25519 uses vendored source (see [Requirements](#requirements))
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

**Release/version note:** The published `HeroSD-JWT` **1.1.7** verifier defaults to `ExpectedKeyType = Either`, while this repository's development source defaults to `Asymmetric`. Choose an explicit policy for your issuer: `Symmetric` for HS* secret keys or `Asymmetric` for RSA/ECDSA public keys. The examples and descriptions below follow development source, and may differ from the installed NuGet version.

## Quick Start

### Simple API (Recommended)

The fluent builder provides an easy, discoverable API. Subsequent snippets reuse imports and variables from the preceding example unless marked as alternatives:

```csharp
using HeroSdJwt.Issuance;
using HeroSdJwt.Cryptography;
using HeroSdJwt.Extensions;

// Generate a signing key
var keyGen = KeyGenerator.Instance;
var key = keyGen.GenerateHmacKey();

// Create SD-JWT with fluent builder
var sdJwt = SdJwtIssuerBuilder.Create()
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
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

// Create SD-JWT with nested object claims
var sdJwt = SdJwtIssuerBuilder.Create()
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
    new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Symmetric },
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
var sdJwt = SdJwtIssuerBuilder.Create()
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
var sdJwt = SdJwtIssuerBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email")
    .SignWithHmac(key)
    .Build();

// RSA (asymmetric, widely supported)
var (rsaPrivate, rsaPublic) = keyGen.GenerateRsaKeyPair();
var sdJwt = SdJwtIssuerBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email")
    .SignWithRsa(rsaPrivate)
    .Build();

// ECDSA (asymmetric, compact)
var (ecPrivate, ecPublic) = keyGen.GenerateEcdsaKeyPair();
var sdJwt = SdJwtIssuerBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email")
    .SignWithEcdsa(ecPrivate)
    .Build();

// Ed25519 (asymmetric, fast, small keys)
var (ed25519Private, ed25519Public) = keyGen.GenerateEd25519KeyPair();
var sdJwt = SdJwtIssuerBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email")
    .SignWithEd25519(ed25519Private)
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
var sdJwt = SdJwtIssuerBuilder.Create()
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
    new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Symmetric },
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
using HeroSdJwt.Primitives;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

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

var signingKey = KeyGenerator.Instance.GenerateHmacKey();
var sdJwt = issuer.CreateSdJwt(
    claims,
    selectivelyDisclosableClaims: new[] { "email" },
    signingKey,
    HashAlgorithm.Sha256,
    SignatureAlgorithm.HS256);
```

- ECDSA signatures (ES256/ES384/ES512) follow the JWS spec and are emitted in JOSE raw `R||S` format (not ASN.1 DER); verifiers accept the JOSE form.
- **Development source** defaults to `ExpectedKeyType = Asymmetric`, while published **1.1.7** defaults to `Either`. Configure `Asymmetric` for RSA/ECDSA public keys or `Symmetric` for HS* secrets; use `Either` only when both are deliberately permitted.
- `SdJwtVerifierBuilder` exposes `.WithExpectedKeyType(...)` so you can wire the key-type policy when constructing verifiers via DI.

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

Continue from the first Advanced API HMAC example (the `email` claim, `sdJwt`, and `signingKey`); the array and asymmetric examples above are separate alternatives.

```csharp
using HeroSdJwt.Presentation;

// Holder receives sdJwt from issuer and creates a presentation
var presenter = new SdJwtPresenter();

var presentation = presenter.CreatePresentation(
    sdJwt,
    selectedClaimNames: new[] { "email" } // Disclose the issuer's email claim
);

// Format for transmission
string presentationString = presenter.FormatPresentation(presentation);
// Format: "eyJhbGc...jwt...~WyI2cU1R...disclosure..."
```

### 3. Verifier: Verify Presentation

```csharp
using HeroSdJwt.Cryptography;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

// Verify presentation
var verifier = new SdJwtVerifier(
    new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Symmetric },
    new EcPublicKeyConverter(),
    new SignatureValidator(),
    new DigestValidator(),
    new KeyBindingValidator(),
    new ClaimValidator());
var verificationKey = signingKey; // Reuse the actual HS256 signing key from the issuer example

// Option 1: Throws exception on failure (recommended for most cases)
var result = verifier.VerifyPresentation(presentationString, verificationKey);
Console.WriteLine($"Email: {result.DisclosedClaims["email"]}");

// Option 2: Returns result without throwing (Try* pattern)
var tryResult = verifier.TryVerifyPresentation(presentationString, verificationKey);
if (tryResult.IsValid)
{
    Console.WriteLine("Verification succeeded!");
    var email = tryResult.DisclosedClaims["email"];
    Console.WriteLine($"Email: {email}");
}
else
{
    Console.WriteLine("Verification failed!");
    foreach (var error in tryResult.Errors)
    {
        Console.WriteLine($"Error: {error}");
    }
}
```

## Architecture

The library follows the three-party SD-JWT model:

```
+---------+                  +--------+                  +----------+
| Issuer  |                  | Holder |                  | Verifier |
+----+----+                  +----+---+                  +----+-----+
     |                            |                           |
     |  1. Create SD-JWT          |                           |
     |  with selective disclosures|                           |
     |--------------------------->|                           |
     |                            |                           |
     |                            |  2. Select claims         |
     |                            |  to disclose              |
     |                            |                           |
     |                            |  3. Create presentation   |
     |                            |-------------------------->|
     |                            |                           |
     |                            |                           |  4. Verify
     |                            |                           |  signature
     |                            |                           |  & digests
     |                            |                           |
```

## Security

**Key Binding audience policy:** The holder-signed KB-JWT `aud` identifies the verifier, which can differ from (or be absent in) the issuer-signed JWT's `aud`. For a holder-bound presentation, configure `RequireKeyBinding = true`, `ExpectedKeyBindingAudience = "https://verifier.example"`, and `ExpectedNonce`. Use `ExpectedAudience` or `ExpectedAudiences` separately if the issuer JWT needs an audience policy. The fluent builder exposes `WithExpectedKeyBindingAudience(...)`. When the new setting is omitted, the previous coupled-audience behavior is preserved for compatibility.

This library implements security best practices:

- **Constant-time comparison**: Uses `CryptographicOperations.FixedTimeEquals` for digest validation to prevent timing attacks
- **Algorithm confusion prevention**: Rejects "none" algorithm (both lowercase and uppercase)
- **Cryptographically secure salts**: Uses `RandomNumberGenerator` for 128-bit salts
- **Dependency transparency**: .NET 8 uses `Microsoft.Bcl.Memory`; Ed25519 includes vendored source. Review package and source provenance as part of security maintenance.
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

- **Package consumers**: supported target frameworks are `net8.0`, `net9.0`, and `net10.0`.
- **Building this repository**: install exactly **.NET SDK 10.0.402** as pinned by [global.json](global.json), with SDK roll-forward disabled. Install the corresponding runtimes to run tests for all three target frameworks.
- **Core package dependencies**: the .NET 8 target references `Microsoft.Bcl.Memory` to provide `Base64Url` APIs; .NET 9/10 use the native BCL APIs.
- **Vendored cryptography**: Ed25519 includes source ported from Chaos.NaCl; see [third-party notices](src/HeroSdJwt/Internal/Ed25519/THIRD-PARTY-NOTICES.txt).

## Native AOT and Trimming Compatibility

Native AOT compatibility depends on the **exact library version, target platform and claim shapes used**. The core uses explicit JSON writing for several internal paths and avoids JWK serialize/deserialize round-trips, but some issuance and nested-claim paths still call `JsonSerializer` internally and carry IL2026/IL3050 suppressions. Do not interpret a successful regular .NET build, or a `JsonElement` input, as proof that every path works with Native AOT and trimming.

- HMAC, RSA and ECDSA use .NET cryptographic APIs; Ed25519 uses vendored source.
- Basic values and pre-parsed JSON can reduce dependence on reflection at the **caller** boundary. Custom object serialization may require source-generated `JsonSerializerContext` and careful preservation of types.
- Test the actual package version, issuing and verifying your application's real claim shapes in a separately published Native AOT consumer. Check trim/AOT warnings instead of relying on a blanket compatibility claim.

For example, prepare a `JsonElement` without reflectively serializing an anonymous caller object:

```csharp
using System.Text.Json;

using var document = JsonDocument.Parse("""{"name":"Alice","age":30}""");
var claims = new Dictionary<string, object>
{
    ["sub"] = "user-123",
    ["profile"] = document.RootElement.Clone()
};
```

This prepares the input only; **the subsequent issuance and verification paths still require application-specific AOT validation**.

## Development

### Building the Project

Source builds require the exact .NET SDK **10.0.402** pinned in `global.json`, independently of the package's .NET 8/9/10 consumption targets. The project uses the modern .slnx solution format:

```bash
# Build the entire solution
dotnet build HeroSD-JWT.slnx

# Build specific configuration
dotnet build HeroSD-JWT.slnx --configuration Release

# Restore dependencies
dotnet restore HeroSD-JWT.slnx
```

All projects multi-target .NET 8.0, .NET 9.0, and .NET 10.0. The build configuration is centrally managed in `Directory.Build.props`.

## Testing

```bash
# Run all tests
dotnet test

# Run with verbose output
dotnet test --verbosity normal

# Run integration tests only (tests are grouped by namespace, not traits)
dotnet test --filter "FullyQualifiedName~HeroSdJwt.Tests.Integration"

# Run unit tests only
dotnet test --filter "FullyQualifiedName~HeroSdJwt.Tests.Unit"

# Run a single test class or method
dotnet test --filter "FullyQualifiedName~SdJwtVerifierTests"
```

### Authentication Policy and Custom Verifiers

`AddSdJwt` applies the complete `VerificationOptions` policy separately for each authentication scheme. The default verifier is request-scoped. Custom verifier implementations must implement `ISdJwtVerifierFactory`, and subclasses of `SdJwtVerifier` must override `CreateVerifier` to preserve their custom behavior when applying the scheme policy.

See [authentication policy migration](docs/users/authentication-policy.md) for the factory contract, dependency lifetimes, and upgrade guidance.

### Distributed Replay Protection & Revocation

For multi-node replay protection, the cache must support **atomic create-if-absent with TTL**. Ordinary `IDistributedCache` implementations are rejected when `DistributedJtiCache` is constructed; a get-then-set sequence cannot prevent concurrent replay.

```csharp
// ApplicationAtomicCache must implement IAtomicDistributedCache using your backend.
builder.Services.AddSingleton<IDistributedCache, ApplicationAtomicCache>();
builder.Services
    .AddSdJwtServices()
    .AddSdJwtDistributedReplayProtection() // Atomic IJtiCache + enabled JtiValidator
    .AddSdJwtDistributedRevocation();      // Separate IRevocationStore adapter
```

No atomic Redis/SQL provider is bundled. You can also register an application-provided `IJtiCache` directly. For distributed JTI **revocation**, the cache must additionally implement `IAtomicRevocationCache` so repeating a revocation can never shorten its expiry. Ordinary `IDistributedCache` remains supported for key/user revocation, but JTI revocation fails closed without that separate atomic capability. See [distributed replay and revocation requirements](docs/users/distributed-replay-protection.md) for both contracts, compatibility, and real-backend validation requirements.

### Continuous Integration

The project includes comprehensive CI/CD workflows:

- **CI Pipeline** ([ci.yml](.github/workflows/ci.yml)) - Runs on every push/PR across all platforms and frameworks
- **Nightly Integration Tests** ([run-integrations.yml](.github/workflows/run-integrations.yml)) - Comprehensive test suite running daily at 2 AM UTC
- **Security Scanning** ([scan-security.yml](.github/workflows/scan-security.yml)) - Automated vulnerability and dependency audits
- **Performance Benchmarks** ([perform-benchmarks.yml](.github/workflows/perform-benchmarks.yml)) - Continuous performance monitoring

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

