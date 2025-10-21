# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-21

### Added
- ( **Core SD-JWT functionality** - Complete implementation of IETF draft-ietf-oauth-selective-disclosure-jwt
- = **Multiple signature algorithms** - Support for HS256 (HMAC), RS256 (RSA), and ES256 (ECDSA)
- <¯ **Array element selective disclosure** - Syntax like `degrees[1]` for individual array elements
- <3 **Nested claims selective disclosure** - Full support for nested properties with `_sd` arrays
- = **Key binding (proof of possession)** - RFC 7800 compliant with temporal validation
- <­ **Decoy digests** - Privacy protection against claim enumeration attacks
- <¨ **Fluent builder API** - Developer-friendly `SdJwtBuilder` for easy SD-JWT creation
- =à **Extension methods** - Convenient helpers like `ToPresentation()` and `ToPresentationWithAllClaims()`
- =' **Dependency injection support** - `IKeyGenerator` interface for testable key generation
- =æ **Zero external dependencies** - Uses only .NET BCL (System.Security.Cryptography, System.Text.Json)
-  **Comprehensive test suite** - 277 passing tests across unit, integration, contract, and security tests
- = **Security hardening**:
  - Constant-time comparison for digest validation (timing attack prevention)
  - Algorithm confusion prevention (rejects "none" algorithm)
  - Critical claim protection (iss, aud, exp, cnf cannot be selective)
  - Key binding JWT temporal validation (replay attack prevention)
  - Cryptographically secure salt generation (128-bit minimum)
- <¯ **Multi-targeting** - Supports .NET 8.0 and .NET 9.0
- =Ö **Complete XML documentation** - All public APIs documented
- = **Source Link support** - Step-through debugging into library source

### Changed
- N/A (initial release)

### Deprecated
- N/A (initial release)

### Removed
- N/A (initial release)

### Fixed
- N/A (initial release)

### Security
- Implemented constant-time digest comparison to prevent timing attacks
- Validated that critical JWT claims cannot be made selectively disclosable
- Added temporal validation for key binding JWTs to prevent replay attacks
- Ensured cryptographically secure random number generation for salts

---

## [Unreleased]

### Planned
- Performance benchmarks with BenchmarkDotNet
- Sample projects and tutorials
- Additional hash algorithm support (SHA3)

[1.0.0]: https://github.com/BeingCiteable/HeroSD-JWT/releases/tag/v1.0.0
[Unreleased]: https://github.com/BeingCiteable/HeroSD-JWT/compare/v1.0.0...HEAD
