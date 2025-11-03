# Future Improvements for HeroSD-JWT

This document tracks architectural improvements identified during the JWT Key Rotation feature implementation (spec 004-jwt-key-rotation).

## 1. Complete Dependency Injection (DI) Refactoring

**Status**: Partially Complete
**Priority**: Medium
**Effort**: Large (~2-3 days)

### Current State

Most classes already have interfaces for DI, but some retain convenience constructors:

**Classes WITH interfaces** ✅:
- ✅ `EcPublicKeyConverter` → `IEcPublicKeyConverter`
- ✅ `JwtSigner` → `IJwtSigner`
- ✅ `KeyGenerator` → `IKeyGenerator`
- ✅ `DecoyDigestGenerator` → `IDecoyDigestGenerator`
- ✅ `DigestCalculator` → `IDigestCalculator`
- ✅ `DisclosureGenerator` → `IDisclosureGenerator`
- ✅ `KeyBindingGenerator` → `IKeyBindingGenerator`
- ✅ `KeyBindingValidator` → `IKeyBindingValidator`
- ✅ `DisclosureClaimPathMapper` → `IDisclosureClaimPathMapper`
- ✅ `DisclosureParser` → `IDisclosureParser`
- ✅ `SdJwtPresenter` → `ISdJwtPresenter`
- ✅ `ClaimValidator` → `IClaimValidator`
- ✅ `DigestValidator` → `IDigestValidator`
- ✅ `SdJwtVerifier` → `ISdJwtVerifier`
- ✅ `SignatureValidator` → `ISignatureValidator`

**Classes MISSING interfaces** ❌:
- ❌ `SdJwtIssuer` (CRITICAL - main issuer class)
- ⚠️ `SdJwtBuilder` (fluent API - interface may not be needed)
- ⚠️ `SdJwtVerificationOptions` (DTO/config - doesn't need interface)

### Problem: Convenience Constructors

Many classes have BOTH:
1. **Convenience constructor**: `new SdJwtVerifier()` → creates default dependencies
2. **DI constructor**: `new SdJwtVerifier(options, converter, validator, ...)` → full control

**Examples**:

```csharp
// SdJwtVerifier has 3 constructors:
public SdJwtVerifier()  // Convenience - creates defaults
public SdJwtVerifier(SdJwtVerificationOptions options)  // Semi-convenience
public SdJwtVerifier(SdJwtVerificationOptions, IEcPublicKeyConverter, ...)  // Full DI

// SdJwtIssuer has 2 constructors:
public SdJwtIssuer()  // Convenience - creates defaults
public SdJwtIssuer(IDisclosureGenerator, IDigestCalculator, ...)  // Full DI

// DecoyDigestGenerator has 2 constructors:
public DecoyDigestGenerator()  // Convenience
public DecoyDigestGenerator(IDigestCalculator)  // Full DI
```

### Recommended Refactoring

#### Phase 1: Create Missing Interfaces

1. **Create `ISdJwtIssuer` interface**:
```csharp
public interface ISdJwtIssuer
{
    SdJwt CreateSdJwt(
        Dictionary<string, object> claims,
        IEnumerable<string> selectivelyDisclosableClaims,
        byte[] signingKey,
        HashAlgorithm hashAlgorithm,
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256,
        byte[]? holderPublicKey = null,
        int decoyDigestCount = 0,
        string? keyId = null);
}

public class SdJwtIssuer : ISdJwtIssuer { ... }
```

#### Phase 2: Remove Convenience Constructors

**Remove** all parameterless and partial constructors, keep **ONLY** the full DI constructor:

```csharp
// BEFORE (multiple constructors)
public class SdJwtVerifier
{
    public SdJwtVerifier() : this(new SdJwtVerificationOptions()) { }
    public SdJwtVerifier(SdJwtVerificationOptions options) : this(options, new EcPublicKeyConverter(), ...) { }
    public SdJwtVerifier(SdJwtVerificationOptions options, IEcPublicKeyConverter ec, ...) { ... }
}

// AFTER (single DI constructor only)
public class SdJwtVerifier : ISdJwtVerifier
{
    /// <summary>
    /// This is the ONLY constructor - use dependency injection.
    /// For simple scenarios: new SdJwtVerifier(new SdJwtVerificationOptions(), new EcPublicKeyConverter(), ...)
    /// </summary>
    public SdJwtVerifier(
        SdJwtVerificationOptions options,
        IEcPublicKeyConverter ecPublicKeyConverter,
        ISignatureValidator signatureValidator,
        IDigestValidator digestValidator,
        IKeyBindingValidator keyBindingValidator,
        IClaimValidator claimValidator)
    {
        // Validate and assign dependencies
    }
}
```

#### Phase 3: Update All Usages

**Impact**: ~86+ test files need updating

```csharp
// BEFORE
var verifier = new SdJwtVerifier();

// AFTER
var verifier = new SdJwtVerifier(
    new SdJwtVerificationOptions(),
    new EcPublicKeyConverter(),
    new SignatureValidator(),
    new DigestValidator(),
    new KeyBindingValidator(),
    new ClaimValidator());
```

**Alternatively**, create factory helpers in tests:
```csharp
// Test helper
public static class TestHelpers
{
    public static ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions? options = null)
    {
        return new SdJwtVerifier(
            options ?? new SdJwtVerificationOptions(),
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(),
            new ClaimValidator());
    }
}
```

#### Phase 4: Update README Documentation

Update all README examples to show DI constructor usage:

```csharp
// Before
var verifier = new SdJwtVerifier();

// After
var verifier = new SdJwtVerifier(
    new SdJwtVerificationOptions(),
    new EcPublicKeyConverter(),
    new SignatureValidator(),
    new DigestValidator(),
    new KeyBindingValidator(),
    new ClaimValidator());

var result = verifier.VerifyPresentation(presentation, publicKey);
```

### Benefits

1. **Testability**: Easy to mock dependencies in unit tests
2. **Consistency**: All classes follow same DI pattern
3. **Explicitness**: Dependencies are visible at construction time
4. **IoC Container Friendly**: Ready for Microsoft.Extensions.DependencyInjection
5. **"Make Illegal States Unrepresentable"**: Can't create objects with invalid dependencies

### Challenges

1. **Breaking Change**: Removes convenience constructors (major version bump)
2. **Verbosity**: Simple scenarios become more verbose
3. **Migration Effort**: All existing code must update constructor calls
4. **Documentation**: Must update all examples and guides

### Alternative: Hybrid Approach

Keep BOTH patterns but document clearly:

```csharp
// Simple/Production usage - convenience
var verifier = new SdJwtVerifier();

// Testing usage - full DI
var verifier = new SdJwtVerifier(
    options,
    mockEcConverter,
    mockSignatureValidator,
    ...);
```

**Pros**:
- No breaking changes
- Supports both simple and advanced scenarios
- Gradual migration path

**Cons**:
- Less consistent
- Multiple ways to do the same thing
- Some constructors call `new` internally (not pure DI)

---

## 2. KeyId as Value Type

**Status**: Not Started
**Priority**: Low
**Effort**: Medium (~1 day)

### Current Implementation

```csharp
// Key ID is validated at method call time
public SdJwtBuilder WithKeyId(string keyId)
{
    Primitives.KeyIdValidator.Validate(keyId);  // Runtime validation
    this.keyId = keyId;
    return this;
}
```

### Recommended Improvement

Create a `KeyId` value type (struct or class) that validates in its constructor:

```csharp
public readonly struct KeyId
{
    private readonly string value;

    public KeyId(string keyId)
    {
        ArgumentNullException.ThrowIfNull(keyId);

        if (string.IsNullOrWhiteSpace(keyId))
            throw new ArgumentException("Key ID cannot be empty", nameof(keyId));

        if (keyId.Length > 256)
            throw new ArgumentException($"Key ID too long: {keyId.Length}", nameof(keyId));

        if (keyId.Any(c => c < 32 || c > 126))
            throw new ArgumentException("Key ID contains non-printable characters", nameof(keyId));

        this.value = keyId;
    }

    public static implicit operator string(KeyId keyId) => keyId.value;
    public static explicit operator KeyId(string keyId) => new KeyId(keyId);

    public override string ToString() => value;
}

// Usage
public SdJwtBuilder WithKeyId(KeyId keyId)  // Validation guaranteed by type system
{
    this.keyId = keyId;  // Can't be invalid!
    return this;
}
```

### Benefits

1. **Type Safety**: Compile-time guarantee that keyId is valid
2. **"Make Illegal States Unrepresentable"**: Can't create invalid KeyId
3. **Eliminates `KeyIdValidator`**: Validation logic in type constructor
4. **Domain-Driven Design**: KeyId is a domain concept, not just a string
5. **Self-Documenting**: `KeyId` type makes intent clear

### Challenges

1. **Breaking Change**: Changes public API signatures
2. **Conversion Overhead**: Requires `new KeyId()` wrapping
3. **Implicit Conversions**: Need careful design to avoid confusion

---

## 3. Microsoft.Extensions.DependencyInjection Integration

**Status**: Not Started
**Priority**: Low
**Effort**: Small (~half day)

Once DI refactoring is complete, add extension methods for ASP.NET Core / Generic Host:

```csharp
public static class HeroSdJwtServiceCollectionExtensions
{
    public static IServiceCollection AddHeroSdJwt(
        this IServiceCollection services,
        Action<SdJwtVerificationOptions>? configureOptions = null)
    {
        // Register all interfaces with implementations
        services.AddSingleton<IEcPublicKeyConverter, EcPublicKeyConverter>();
        services.AddSingleton<IJwtSigner, JwtSigner>();
        services.AddSingleton<IKeyGenerator, KeyGenerator>();
        services.AddSingleton<IDecoyDigestGenerator, DecoyDigestGenerator>();
        services.AddSingleton<IDigestCalculator, DigestCalculator>();
        services.AddSingleton<IDisclosureGenerator, DisclosureGenerator>();
        services.AddSingleton<IKeyBindingGenerator, KeyBindingGenerator>();
        services.AddSingleton<IKeyBindingValidator, KeyBindingValidator>();
        services.AddSingleton<IDisclosureClaimPathMapper, DisclosureClaimPathMapper>();
        services.AddSingleton<IDisclosureParser, DisclosureParser>();
        services.AddSingleton<ISdJwtPresenter, SdJwtPresenter>();
        services.AddSingleton<IClaimValidator, ClaimValidator>();
        services.AddSingleton<IDigestValidator, DigestValidator>();
        services.AddSingleton<ISdJwtVerifier, SdJwtVerifier>();
        services.AddSingleton<ISignatureValidator, SignatureValidator>();
        services.AddSingleton<ISdJwtIssuer, SdJwtIssuer>();  // After creating interface

        // Configure options
        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }
        else
        {
            services.AddSingleton(new SdJwtVerificationOptions());
        }

        return services;
    }
}

// Usage in ASP.NET Core
builder.Services.AddHeroSdJwt(options => {
    options.ClockSkew = TimeSpan.FromMinutes(5);
    options.RequireKeyBinding = true;
});
```

---

## Implementation Checklist

When implementing the full DI refactoring:

### Pre-Implementation
- [ ] Create feature branch `refactor/complete-di-pattern`
- [ ] Document current API usage in tests (for migration guide)
- [ ] Set up baseline performance benchmarks

### Phase 1: Interfaces
- [ ] Create `ISdJwtIssuer` interface
- [ ] Update `SdJwtIssuer` to implement interface
- [ ] Verify all other classes have interfaces
- [ ] Add XML documentation to all interfaces

### Phase 2: Remove Convenience Constructors
- [ ] Remove from `SdJwtVerifier` (keep only DI constructor)
- [ ] Remove from `SdJwtIssuer`
- [ ] Remove from `DecoyDigestGenerator`
- [ ] Remove from any other classes with multiple constructors
- [ ] Add XML doc comments showing "simple usage" example

### Phase 3: Update Source Code
- [ ] Update `SdJwtBuilder` internal usage
- [ ] Update any other internal usages in src/
- [ ] Add `using HeroSdJwt.Cryptography;` where needed

### Phase 4: Update Tests (Largest Effort)
- [ ] Create test helper factory methods
- [ ] Update all 86+ test files to use DI constructors
- [ ] Add missing `using` directives to test files
- [ ] Remove duplicate `using` statements
- [ ] Verify all 433 tests still pass

### Phase 5: Documentation
- [ ] Update README.md examples
- [ ] Update CLAUDE.md if needed
- [ ] Create migration guide for users
- [ ] Update quickstart.md examples

### Phase 6: Validation
- [ ] Run full test suite (should be 433 passing)
- [ ] Run performance benchmarks (ensure no regression)
- [ ] Run `dotnet format` for consistency
- [ ] Verify zero compiler warnings
- [ ] Manual testing of key scenarios

### Phase 7: Release
- [ ] Update CHANGELOG.md (breaking change!)
- [ ] Bump major version (3.0.0 or similar)
- [ ] Create PR with detailed description
- [ ] Tag release after merge

---

## Estimated Timeline

- **Phase 1 (Interfaces)**: 2 hours
- **Phase 2 (Remove constructors)**: 1 hour
- **Phase 3 (Update source)**: 2 hours
- **Phase 4 (Update tests)**: 8-12 hours (largest effort!)
- **Phase 5 (Documentation)**: 3 hours
- **Phase 6 (Validation)**: 2 hours
- **Phase 7 (Release)**: 1 hour

**Total**: ~20-24 hours (2-3 full days)

---

## Decision: Why Not Now?

This refactoring was **deferred** during JWT Key Rotation implementation (spec 004-jwt-key-rotation) because:

1. **Feature Complete**: All 433 tests passing, feature fully working
2. **Token Budget**: Already at 63% token usage (126K/200K)
3. **Scope Creep**: This is architectural refactoring, not feature work
4. **Risk**: Large refactoring touching 86+ files increases bug risk
5. **Separate Concern**: DI pattern is orthogonal to key rotation feature
6. **Better as PR**: Deserves dedicated PR with focused testing

**Recommendation**: Implement this in a separate PR after 004-jwt-key-rotation is merged and released.

---

*Document created: 2025-10-25*
*Last updated: 2025-10-25*
*Related: JWT Key Rotation Feature (spec 004-jwt-key-rotation)*
