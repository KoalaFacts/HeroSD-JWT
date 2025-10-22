# GitHub Issue: Support for Nested Property and Array Element Presentations

**Project**: HeroSD-JWT
**Issue Type**: Enhancement / Bug Fix
**Priority**: High
**Affects**: Presentation creation, Verification, Testing

## Summary

The library currently cannot create selective disclosure presentations for nested object properties or array elements. When `MakeSelective()` is called with paths like `"address.street"` or `"degrees[0]"`, the disclosures are created but stored with leaf names only. Subsequently, `ToPresentation()` cannot find these disclosures when using the full path syntax, making it impossible to create presentations for structured claims.

## Current Behavior

### Nested Object Properties

```csharp
// Creating SD-JWT with nested property disclosures
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("address", new { street = "123 Main St", city = "Boston" })
    .MakeSelective("address.street", "address.city")  // ✅ Parses syntax correctly
    .SignWithHmac(signingKey)
    .Build();

// Attempting to create presentation
var presentation = sdJwt.ToPresentation("address.street", "address.city");
// ❌ FAILS: ArgumentException: Claim 'address.street' not found in SD-JWT disclosures.
// Available claims: street, city
```

### Array Elements

```csharp
// Creating SD-JWT with array element disclosures
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("degrees", new[] { "PhD", "MBA", "BSc" })
    .MakeSelective("degrees[0]", "degrees[1]")  // ❌ Silently ignored or fails
    .SignWithHmac(signingKey)
    .Build();

// Even if disclosures were created, presentation would fail
var presentation = sdJwt.ToPresentation("degrees[0]", "degrees[1]");
// ❌ FAILS: Claim 'degrees[0]' not found
```

## Expected Behavior

1. `MakeSelective("address.street")` should store the disclosure with the **full path** as the claim identifier
2. `ToPresentation("address.street")` should successfully find and include the disclosure
3. `VerificationResult.DisclosedClaims` should contain entries like:
   - Key: `"address.street"`, Value: `"123 Main St"`
   - Key: `"degrees[0]"`, Value: `"PhD"`

## Root Cause Analysis

### 1. SdJwtBuilder.MakeSelective()
**Location**: (Need to identify exact file/line)

The method correctly parses nested property syntax but stores disclosures using only the **leaf property name**:
- Input: `"address.street"`
- Stored as: `"street"`
- Should store as: `"address.street"`

### 2. SdJwtPresenter.CreatePresentation()
**Location**: `src/Presentation/SdJwtPresenter.cs:45`

The method searches for claims by the **full path** provided in `selectedClaimNames`, but the disclosures were stored with leaf names only, causing a lookup failure.

**Error thrown**:
```
System.ArgumentException: Claim 'address.street' not found in SD-JWT disclosures.
Available claims: street, city (Parameter 'selectedClaimNames')
```

### 3. SdJwtVerifier.ExtractDisclosedClaims()
**Location**: `src/Verification/SdJwtVerifier.cs:438-501`

The method extracts 3-element object property disclosures but stores them in `DisclosedClaims` with **simple claim names only** (no dot notation or path context).

**Code comment at line 437**:
```csharp
/// Note: Array element disclosures are validated but not currently reconstructed into arrays.
```

Array element disclosures (2-element format: `[salt, value]`) are validated but **never added to the DisclosedClaims dictionary**.

## Impact

### On Testing
- **Cannot create test presentations** for nested object properties
- **Cannot create test presentations** for array elements
- Makes it impossible to test SD-JWT features that rely on structured claims
- Blocks comprehensive testing of reconstruction APIs

### On Production Use
- Limits library to **simple, flat claims only**
- Cannot selectively disclose nested properties in complex objects
- Cannot selectively disclose individual array elements
- Significantly reduces real-world applicability

### On Specification Compliance
The SD-JWT specification (RFC draft) supports selective disclosure of:
- Nested object properties
- Array elements

The current implementation is **incomplete** relative to the specification.

## Proposed Solution

### Phase 1: Nested Object Properties (Higher Priority)

1. **Modify `SdJwtBuilder.MakeSelective()`**:
   - Store disclosures with full path as claim name
   - For `MakeSelective("address.street")`, store disclosure as: `["salt", "address.street", "123 Main St"]`

2. **Modify `SdJwtVerifier.ExtractDisclosedClaims()`**:
   - Preserve full path in `DisclosedClaims` dictionary
   - Parse claim names that contain dots as nested properties
   - Add entries like: `disclosedClaims["address.street"] = jsonValue`

3. **Update `SdJwtPresenter.CreatePresentation()`**:
   - Search for claims using full paths (should work once steps 1-2 are complete)

### Phase 2: Array Elements

1. **Modify `SdJwtBuilder.MakeSelective()`**:
   - Support array element syntax: `MakeSelective("degrees[0]")`
   - Create 2-element array disclosures: `["salt", "PhD"]`
   - Track array element metadata (parent claim name, index)

2. **Modify `SdJwtVerifier.ExtractDisclosedClaims()`**:
   - Add array element disclosures to `DisclosedClaims`
   - Use full path as key: `"degrees[0]"`, `"degrees[1]"`
   - Current code validates but doesn't add them (lines 474-481)

3. **Consider new data structure**:
   - Current: `Dictionary<string, JsonElement>` for simple claims only
   - Proposed: Support path syntax in keys or use structured representation

## Workarounds (Current)

None available. The library currently **cannot create presentations** for anything except simple, flat claims.

## Test Case

```csharp
[Fact]
public void ToPresentation_WithNestedProperties_ShouldSucceed()
{
    // Arrange
    var signingKey = GenerateTestKey();
    var sdJwt = SdJwtBuilder.Create()
        .WithClaim("address", new
        {
            street = "123 Main St",
            city = "Boston",
            geo = new { lat = 42.3601, lon = -71.0589 }
        })
        .MakeSelective("address.street", "address.city", "address.geo.lat")
        .SignWithHmac(signingKey)
        .Build();

    // Act
    var presentation = sdJwt.ToPresentation("address.street", "address.city");

    // Assert
    var verifier = new SdJwtVerifier();
    var result = verifier.VerifyPresentation(presentation, signingKey);

    Assert.True(result.IsValid);
    Assert.True(result.DisclosedClaims.ContainsKey("address.street"));
    Assert.Equal("123 Main St", result.DisclosedClaims["address.street"].GetString());
    Assert.True(result.DisclosedClaims.ContainsKey("address.city"));
    Assert.Equal("Boston", result.DisclosedClaims["address.city"].GetString());
    Assert.False(result.DisclosedClaims.ContainsKey("address.geo.lat")); // Not revealed
}

[Fact]
public void ToPresentation_WithArrayElements_ShouldSucceed()
{
    // Arrange
    var signingKey = GenerateTestKey();
    var sdJwt = SdJwtBuilder.Create()
        .WithClaim("degrees", new[] { "PhD in Computer Science", "MBA", "BSc in Mathematics" })
        .MakeSelective("degrees[0]", "degrees[2]")
        .SignWithHmac(signingKey)
        .Build();

    // Act
    var presentation = sdJwt.ToPresentation("degrees[0]", "degrees[2]");

    // Assert
    var verifier = new SdJwtVerifier();
    var result = verifier.VerifyPresentation(presentation, signingKey);

    Assert.True(result.IsValid);
    Assert.True(result.DisclosedClaims.ContainsKey("degrees[0]"));
    Assert.Equal("PhD in Computer Science", result.DisclosedClaims["degrees[0]"].GetString());
    Assert.True(result.DisclosedClaims.ContainsKey("degrees[2]"));
    Assert.Equal("BSc in Mathematics", result.DisclosedClaims["degrees[2]"].GetString());
    Assert.False(result.DisclosedClaims.ContainsKey("degrees[1]")); // Not revealed
}
```

## Related Work

This issue was discovered while implementing **Array Reconstruction API** (feature 002) which provides extension methods to reconstruct arrays and objects from selective disclosures:
- `GetDisclosedArray()` - Reconstructs sparse arrays
- `GetDisclosedObject()` - Reconstructs hierarchical objects
- `GetReconstructibleClaims()` - Discovers reconstructible claims

These methods are **fully implemented and production-ready**, but cannot be comprehensively tested due to this library limitation.

## Files Affected

- `src/Issuance/SdJwtBuilder.cs` - MakeSelective() storage logic
- `src/Presentation/SdJwtPresenter.cs:45` - Claim lookup in CreatePresentation()
- `src/Verification/SdJwtVerifier.cs:438-501` - ExtractDisclosedClaims() method
- Test files throughout the codebase

## References

- SD-JWT Specification: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/
- Implementation evidence: `ARRAY-ELEMENT-LIMITATION.md`
- Reconstruction API: `src/Core/ExtensionsToVerificationResult.cs`

## Additional Context

The library's `ClaimPath` parser (if it exists) or equivalent logic already supports parsing nested property and array element syntax - this is evident from `MakeSelective()` accepting these strings without immediate error. The issue is purely in **storage and retrieval**, not parsing.

---

**Reporter**: Implementation team for Array Reconstruction API
**Date**: 2025-10-22
**Severity**: High - Blocks testing and limits production applicability
**Reproducibility**: Always
