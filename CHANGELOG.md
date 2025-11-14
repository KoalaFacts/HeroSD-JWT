# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-21

### Added
- ( **Core SD-JWT functionality** - Complete implementation of IETF draft-ietf-oauth-selective-disclosure-jwt
- = **Multiple signature algorithms** - Support for HS256 (HMAC), RS256 (RSA), and ES256 (ECDSA)
- <� **Array element selective disclosure** - Syntax like `degrees[1]` for individual array elements
- <3 **Nested claims selective disclosure** - Full support for nested properties with `_sd` arrays
- = **Key binding (proof of possession)** - RFC 7800 compliant with temporal validation
- <� **Decoy digests** - Privacy protection against claim enumeration attacks
- <� **Fluent builder API** - Developer-friendly `SdJwtBuilder` for easy SD-JWT creation
- =� **Extension methods** - Convenient helpers like `ToPresentation()` and `ToPresentationWithAllClaims()`
- =' **Dependency injection support** - `IKeyGenerator` interface for testable key generation
- =� **Zero external dependencies** - Uses only .NET BCL (System.Security.Cryptography, System.Text.Json)
-  **Comprehensive test suite** - 277 passing tests across unit, integration, contract, and security tests
- = **Security hardening**:
  - Constant-time comparison for digest validation (timing attack prevention)
  - Algorithm confusion prevention (rejects "none" algorithm)
  - Critical claim protection (iss, aud, exp, cnf cannot be selective)
  - Key binding JWT temporal validation (replay attack prevention)
  - Cryptographically secure salt generation (128-bit minimum)
- <� **Multi-targeting** - Supports .NET 8.0 and .NET 9.0
- =� **Complete XML documentation** - All public APIs documented
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

## [1.0.7] - 2025-11-03

### Added
- 📚 **Comprehensive documentation** in `docs/` directory:
  - `getting-started.md` - Installation and first steps guide
  - `examples.md` - Detailed code examples for various scenarios
  - `security.md` - Security best practices and considerations
  - `api-reference.md` - Complete API documentation
  - `README.md` - Documentation index
- 📝 **CONTRIBUTING.md** - Detailed contribution guidelines
- 🎨 **Enhanced README badges** - Added 11 status badges with shields.io integration

### Changed
- 🔧 Fixed GitHub username references (BeingCiteable → KoalaFacts) across all documentation
- 🔧 Updated README with table of contents for better navigation
- 🔧 Enhanced Contributing section in README with step-by-step guide

### Fixed
- 📄 Fixed LICENSE copyright holder
- 🔗 Fixed broken documentation references in README

---

## [1.1.0] - 2025-11-14

### Added
- 🔄 **JWT Key Rotation Support** - Complete key rotation functionality for enterprise scenarios
  - `WithKeyId(string keyId)` method to specify key identifier in JWT header
  - `KeyResolver` delegate pattern for dynamic key resolution during verification
  - `SdJwtVerifier.VerifyPresentation()` overload with `KeyResolver` parameter
  - `KeyIdValidator` for validating key ID format (256 char limit, printable ASCII)
  - Backward compatible - key ID is optional, falls back to default key if not specified
  - **445 comprehensive tests** covering all key rotation scenarios

- 📊 **Array Reconstruction API** - Extract and reconstruct selective disclosure data
  - `GetDisclosedArray<T>()` - Reconstruct arrays with sparse element support
  - `GetDisclosedObject()` - Reconstruct nested objects with hierarchical structure
  - `GetReconstructibleClaims()` - Discover which claims can be reconstructed
  - Support for complex nested structures (e.g., `address.street`, `degrees[1].university`)
  - **63 comprehensive tests** written (implementation production-ready)

- 🎯 **.NET 10.0 Support** - Multi-targeting extended to include .NET 10.0
  - Target frameworks: net8.0 (LTS), net9.0, net10.0
  - Full compatibility across all three frameworks
  - **1,894 tests passing** across all target frameworks

- 📋 **SBOM (Software Bill of Materials)** - Supply chain security and transparency
  - Per-framework SBOMs (net8.0, net9.0, net10.0) for accurate dependency tracking
  - SPDX 2.2 format for maximum compatibility with current tools
  - SPDX 3.0 format for future-proofing
  - Automated generation in release pipeline (parallel matrix, fail-fast)
  - 6 total SBOMs per release (3 frameworks × 2 formats)
  - Meets US Executive Order 14028 and enterprise compliance requirements

### Changed
- 🔧 Enhanced `SdJwtVerifier` with interface support (`ISdJwtVerifier`) for better dependency injection
- 🔧 Improved error messages for key resolution failures
- 🔧 Updated package description to include array reconstruction and key rotation features

### Fixed
- N/A

### Security
- ✅ Key ID validation prevents injection attacks (limited to printable ASCII, 256 char max)
- ✅ Key resolver exceptions are properly caught and reported
- ✅ Backward compatible key fallback maintains existing security guarantees

### Notes
- Array reconstruction implementation is production-ready and spec-compliant
- Array reconstruction tests documented in `specs/002-array-reconstruction-api/ARRAY-ELEMENT-LIMITATION.md`
- Key rotation lifecycle (User Story 3) is optional and planned for future release

---

## [Unreleased]

### Planned
- Performance benchmarks with BenchmarkDotNet
- Sample projects and tutorials
- Additional hash algorithm support (SHA3)
- Key rotation lifecycle workflows (overlap period, key removal)

[1.1.0]: https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.1.0
[1.0.7]: https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.0.7
[1.0.0]: https://github.com/KoalaFacts/HeroSD-JWT/releases/tag/v1.0.0
[Unreleased]: https://github.com/KoalaFacts/HeroSD-JWT/compare/v1.1.0...HEAD
