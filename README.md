# HeroSD-JWT

A .NET library implementing SD-JWT (Selective Disclosure for JSON Web Tokens) according to the IETF [draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) specification.

## Overview

SD-JWT enables privacy-preserving credential sharing by allowing holders to selectively disclose only necessary claims to verifiers, while cryptographically proving the disclosed claims are authentic and unmodified.

**Key Features**:
- ✅ Create SD-JWTs with selectively disclosable claims
- ✅ Holder-controlled claim disclosure
- ✅ Cryptographic verification of signatures and claim integrity
- ✅ Zero external dependencies (uses only .NET BCL)
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

### 1. Issuer: Create SD-JWT

```csharp
using HeroSdJwt.Issuance;
using HeroSdJwt.Common;

// Define claims
var claims = new Dictionary<string, object>
{
    ["sub"] = "user-123",
    ["name"] = "Alice Example",
    ["birthdate"] = "1990-01-01",
    ["email"] = "alice@example.com"
};

// Create SD-JWT with selective disclosure
var issuer = new SdJwtIssuer();
var signingKey = new byte[32]; // Your HMAC key (HS256)
// For production, use RSA or ECDSA keys

var sdJwt = issuer.CreateSdJwt(
    claims,
    selectivelyDisclosableClaims: new[] { "birthdate", "email" },
    signingKey,
    HashAlgorithm.Sha256
);

// sdJwt.Jwt contains the signed JWT
// sdJwt.Disclosures contains disclosure documents
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

var result = verifier.VerifyPresentation(
    jwt,
    disclosures,
    verificationKey,
    new SdJwtVerificationOptions
    {
        ClockSkew = TimeSpan.FromMinutes(5)
    }
);

// Check result
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
- **No external dependencies**: Zero supply chain risk (uses only .NET BCL)
- **Strict validation**: Treats warnings as errors, validates all inputs

### Supported Algorithms

- **Hash algorithms**: SHA-256 (default), SHA-384, SHA-512
- **Signature algorithms**: HS256 (HMAC-SHA256) currently implemented
  - Future: RS256 (RSA), ES256 (ECDSA)

## Requirements

- **.NET 8.0** or **.NET 9.0**
- No external dependencies

## Testing

```bash
# Run all tests
dotnet test

# Run with verbose output
dotnet test --verbosity normal
```

Current test coverage: 42 passing tests across:
- Contract tests (API behavior)
- Unit tests (component logic)
- Security tests (timing attacks, algorithm confusion, salt entropy)

## Performance

- **Verification**: < 100ms for 50-claim SD-JWTs
- **Processing**: < 500ms for 100-claim SD-JWTs
- **Thread-agnostic design**: Reuse `SdJwtIssuer`, `SdJwtPresenter`, `SdJwtVerifier` instances (you handle synchronization)

## Roadmap

- [ ] Key binding (proof of possession)
- [ ] Nested claims selective disclosure
- [ ] Array element selective disclosure
- [ ] Decoy digests for privacy enhancement
- [ ] RS256/ES256 signature algorithm support
- [ ] Integration tests for end-to-end flows
- [ ] Performance benchmarks

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Write tests first (TDD)
2. Ensure all tests pass
3. Follow .NET naming conventions
4. Add XML documentation for public APIs
5. No external dependencies (BCL only)

## License

MIT License - see [LICENSE](LICENSE) file for details

## References

- **Specification**: [IETF draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- **Repository**: https://github.com/BeingCiteable/HeroSD-JWT
- **Quick Start**: See [specs/001-sd-jwt-library/quickstart.md](specs/001-sd-jwt-library/quickstart.md)
- **Implementation Plan**: See [specs/001-sd-jwt-library/plan.md](specs/001-sd-jwt-library/plan.md)

## Support

- **Issues**: Report bugs at https://github.com/BeingCiteable/HeroSD-JWT/issues
- **Discussions**: Community support via GitHub Discussions

---

**Status**: ✅ Core functionality complete (Issuance, Presentation, Verification)

**Version**: 0.1.0-alpha (pre-release)
