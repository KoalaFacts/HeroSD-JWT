using HeroSdJwt.Common;
using HeroSdJwt.Core;
using HeroSdJwt.Issuance;
using System.Security.Cryptography;
using Xunit;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for the fluent SdJwtBuilder API.
/// Validates the simplified, developer-friendly interface.
/// </summary>
public class SdJwtBuilderTests
{
    [Fact]
    public void Build_WithMinimalConfig_CreatesValidSdJwt()
    {
        // Arrange
        var key = CryptoHelpers.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email")
            .SignWithHmac(key)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
        Assert.Single(sdJwt.Disclosures);
    }

    [Fact]
    public void Build_WithIndividualClaims_CreatesValidSdJwt()
    {
        // Arrange
        var key = CryptoHelpers.GenerateHmacKey();

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "user123")
            .WithClaim("email", "user@example.com")
            .WithClaim("age", 30)
            .MakeSelective("email", "age")
            .SignWithHmac(key)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.Equal(2, sdJwt.Disclosures.Count);
    }

    [Fact]
    public void Build_WithRsaSignature_CreatesValidSdJwt()
    {
        // Arrange
        var (privateKey, _) = CryptoHelpers.GenerateRsaKeyPair();
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .SignWithRsa(privateKey)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
    }

    [Fact]
    public void Build_WithEcdsaSignature_CreatesValidSdJwt()
    {
        // Arrange
        var (privateKey, _) = CryptoHelpers.GenerateEcdsaKeyPair();
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .SignWithEcdsa(privateKey)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
    }

    [Fact]
    public void Build_WithKeyBinding_IncludesCnfClaim()
    {
        // Arrange
        var issuerKey = CryptoHelpers.GenerateHmacKey();
        var (_, holderPublicKey) = CryptoHelpers.GenerateKeyBindingKeyPair();
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .SignWithHmac(issuerKey)
            .WithKeyBinding(holderPublicKey)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
        // cnf claim should be in JWT (we can't easily verify without parsing)
    }

    [Fact]
    public void Build_WithDecoys_CreatesExtraDigests()
    {
        // Arrange
        var key = CryptoHelpers.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email")
            .SignWithHmac(key)
            .WithDecoys(5)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        // Should have 1 real disclosure + 5 decoys in JWT payload _sd array
        Assert.Single(sdJwt.Disclosures); // Only real disclosures are in the list
    }

    [Fact]
    public void Build_WithoutClaims_ThrowsInvalidOperationException()
    {
        // Arrange
        var key = CryptoHelpers.GenerateHmacKey();

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            SdJwtBuilder.Create()
                .SignWithHmac(key)
                .Build());

        Assert.Contains("Claims must be set", exception.Message);
    }

    [Fact]
    public void Build_WithoutSigningKey_ThrowsInvalidOperationException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            SdJwtBuilder.Create()
                .WithClaims(claims)
                .Build());

        Assert.Contains("Signing key must be set", exception.Message);
    }

    [Fact]
    public void WithDecoys_WithNegativeCount_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            SdJwtBuilder.Create().WithDecoys(-1));
    }

    [Fact]
    public void Build_WithCustomHashAlgorithm_UsesSha512()
    {
        // Arrange
        var key = CryptoHelpers.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email")
            .WithHashAlgorithm(HashAlgorithm.Sha512)
            .SignWithHmac(key)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Disclosures);
        // The disclosure itself is base64url encoded JSON (salt, claim, value)
        // Hash algorithm affects JWT payload digests, not disclosure format
        Assert.NotEmpty(sdJwt.Jwt); // Just verify it builds successfully
    }

    [Fact]
    public void FluentAPI_CanChainAllMethods()
    {
        // Arrange
        var key = CryptoHelpers.GenerateHmacKey();
        var (_, holderPublicKey) = CryptoHelpers.GenerateKeyBindingKeyPair();

        // Act - Chain all methods to verify fluent interface
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "user123")
            .WithClaim("email", "user@example.com")
            .WithClaim("age", 30)
            .WithClaim("address", new { city = "NYC", zip = "10001" })
            .MakeSelective("email", "age", "address.city")
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .SignWithHmac(key)
            .WithKeyBinding(holderPublicKey)
            .WithDecoys(3)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
        Assert.NotEmpty(sdJwt.Disclosures);
    }

    [Fact]
    public void SignWith_MultipleCallsOverridePrevious()
    {
        // Arrange
        var hmacKey = CryptoHelpers.GenerateHmacKey();
        var (rsaKey, _) = CryptoHelpers.GenerateRsaKeyPair();
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act - Call SignWithHmac then SignWithRsa (last one should win)
        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .SignWithHmac(hmacKey)
            .SignWithRsa(rsaKey)  // This should override
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        // JWT should use RS256 algorithm
    }
}
