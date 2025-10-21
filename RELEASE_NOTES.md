# HeroSD-JWT v1.0.0 Release Notes

## <‰ Production Release - January 21, 2025

We're excited to announce the first stable release of **HeroSD-JWT**, a production-ready .NET library implementing the IETF SD-JWT (Selective Disclosure for JSON Web Tokens) specification.

## =æ Installation

```bash
dotnet add package HeroSD-JWT
```

Or via NuGet Package Manager:
```powershell
Install-Package HeroSD-JWT
```

## ( Key Features

### Core Functionality
-  **Complete SD-JWT implementation** conforming to IETF draft-ietf-oauth-selective-disclosure-jwt
-  **Three-party model** - Issuer, Holder, and Verifier support
-  **Zero external dependencies** - Uses only .NET BCL

### Advanced Features
- = **Multiple signature algorithms** - HS256 (HMAC), RS256 (RSA), ES256 (ECDSA)
- <¯ **Array element selective disclosure** - Fine-grained control with syntax like `degrees[1]`
- <3 **Nested claims** - Full support for nested JSON objects with selective disclosure
- = **Key binding (RFC 7800)** - Proof of possession with temporal validation
- <­ **Decoy digests** - Privacy protection against claim enumeration attacks

### Developer Experience
- <¨ **Fluent builder API** - Easy-to-use `SdJwtBuilder` with method chaining
- =à **Extension methods** - Convenient helpers like `.ToPresentation()`
- =' **Dependency injection** - `IKeyGenerator` interface for testable designs
- =Ö **Complete XML documentation** - IntelliSense support for all public APIs
- = **Source Link enabled** - Step-through debugging into library source

### Security & Quality
- = **Security hardening**:
  - Constant-time comparison (timing attack prevention)
  - Algorithm confusion prevention
  - Critical claim protection
  - Replay attack prevention
  - Cryptographically secure RNG
-  **277 passing tests** - Comprehensive test coverage
- <¯ **Multi-targeting** - Supports .NET 8.0 and .NET 9.0
- ¡ **Performance** - <100ms verification for 50-claim SD-JWTs

## =€ Quick Start

```csharp
using HeroSdJwt.Issuance;
using HeroSdJwt.Common;

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

## =Ê Test Coverage

- **Unit tests**: Core component logic
- **Integration tests**: End-to-end flows
- **Contract tests**: Public API behavior
- **Security tests**: Timing attacks, algorithm confusion, entropy validation

**Total**: 277 passing tests with 0 warnings and 0 errors

## = Migration Guide

This is the initial stable release. For pre-release users:

### Breaking Changes from Pre-release
- Removed `CryptoHelpers` static class ’ Use `KeyGenerator.Instance`
- `Base64UrlEncoder` is now `internal` ’ Not intended for public use

### Migration Example
```csharp
// Before (pre-release)
var key = CryptoHelpers.GenerateHmacKey();

// After (v1.0.0)
var keyGen = KeyGenerator.Instance;
var key = keyGen.GenerateHmacKey();
```

## <¯ Roadmap

### v1.x Planned Features
- Performance benchmarks with BenchmarkDotNet
- Sample projects and tutorials
- Additional hash algorithm support (SHA3)

### Future Considerations
- Additional signature algorithms (PS256, EdDSA)
- Structured disclosure path helpers
- Alternative serialization options

## =Ú Resources

- **GitHub Repository**: https://github.com/BeingCiteable/HeroSD-JWT
- **NuGet Package**: https://www.nuget.org/packages/HeroSD-JWT
- **Documentation**: See [README.md](README.md)
- **Specification**: [IETF SD-JWT Draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)

## =O Acknowledgments

Thank you to the IETF OAuth Working Group for the SD-JWT specification and to the .NET community for feedback during development.

## =Ä License

MIT License - see [LICENSE](LICENSE) file for details

---

**Questions or Issues?** Open an issue at https://github.com/BeingCiteable/HeroSD-JWT/issues
