using HeroSdJwt.Tests;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using System.Text.Json;
using Xunit;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// Contract tests for SdJwtIssuer API.
/// These tests define the expected behavior and API contract.
/// Written BEFORE implementation (TDD).
/// </summary>
public class SdJwtIssuerContractTests
{
    [Fact]
    public void CreateSdJwt_WithValidClaims_ReturnsValidSdJwt()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" },
            { "age", 30 }
        };

        var selectivelyDisclosableClaims = new[] { "email", "age" };
        var hashAlgorithm = HashAlgorithm.Sha256;
        var signingKey = GenerateMockSigningKey();

        var issuer = TestHelpers.CreateIssuer();

        // Act
        var result = issuer.CreateSdJwt(claims, selectivelyDisclosableClaims, signingKey, hashAlgorithm);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Jwt);
        Assert.NotEmpty(result.Jwt);
        Assert.Equal(hashAlgorithm, result.HashAlgorithm);
        Assert.Equal(2, result.Disclosures.Count); // 2 selectively disclosable claims
        Assert.Null(result.KeyBindingJwt); // No key binding by default
    }

    [Fact]
    public void CreateSdJwt_WithNoSelectiveClaims_ReturnsJwtWithNoDisclosures()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" }
        };

        var selectivelyDisclosableClaims = Array.Empty<string>();
        var hashAlgorithm = HashAlgorithm.Sha256;
        var signingKey = GenerateMockSigningKey();

        var issuer = TestHelpers.CreateIssuer();

        // Act
        var result = issuer.CreateSdJwt(claims, selectivelyDisclosableClaims, signingKey, hashAlgorithm);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Jwt);
        Assert.Empty(result.Disclosures);
    }

    [Fact]
    public void CreateSdJwt_WithNullClaims_ThrowsArgumentNullException()
    {
        // Arrange
        var selectivelyDisclosableClaims = new[] { "email" };
        var hashAlgorithm = HashAlgorithm.Sha256;
        var signingKey = GenerateMockSigningKey();

        var issuer = TestHelpers.CreateIssuer();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            issuer.CreateSdJwt(null!, selectivelyDisclosableClaims, signingKey, hashAlgorithm));
    }

    [Fact]
    public void CreateSdJwt_WithNullSigningKey_ThrowsArgumentNullException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { { "sub", "user123" } };
        var selectivelyDisclosableClaims = new[] { "email" };
        var hashAlgorithm = HashAlgorithm.Sha256;

        var issuer = TestHelpers.CreateIssuer();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            issuer.CreateSdJwt(claims, selectivelyDisclosableClaims, null!, hashAlgorithm));
    }

    [Fact]
    public void CreateSdJwt_JwtContainsSdAlgClaim()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" }
        };

        var selectivelyDisclosableClaims = new[] { "email" };
        var hashAlgorithm = HashAlgorithm.Sha384;
        var signingKey = GenerateMockSigningKey();

        var issuer = TestHelpers.CreateIssuer();

        // Act
        var result = issuer.CreateSdJwt(claims, selectivelyDisclosableClaims, signingKey, hashAlgorithm);

        // Assert
        // Decode JWT payload and verify _sd_alg is present
        var payload = DecodeJwtPayload(result.Jwt);
        Assert.True(payload.TryGetProperty("_sd_alg", out var sdAlg));
        Assert.Equal("sha-384", sdAlg.GetString());
    }

    [Fact]
    public void CreateSdJwt_JwtContainsSdArrayWithDigests()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" },
            { "age", 30 }
        };

        var selectivelyDisclosableClaims = new[] { "email", "age" };
        var hashAlgorithm = HashAlgorithm.Sha256;
        var signingKey = GenerateMockSigningKey();

        var issuer = TestHelpers.CreateIssuer();

        // Act
        var result = issuer.CreateSdJwt(claims, selectivelyDisclosableClaims, signingKey, hashAlgorithm);

        // Assert
        var payload = DecodeJwtPayload(result.Jwt);
        Assert.True(payload.TryGetProperty("_sd", out var sdArray));
        Assert.Equal(JsonValueKind.Array, sdArray.ValueKind);
        Assert.Equal(2, sdArray.GetArrayLength());
    }

    // Helper methods for test setup
    private static byte[] GenerateMockSigningKey()
    {
        // For now, return a simple byte array
        // Will be replaced with proper key generation in implementation
        return new byte[32];
    }

    private static JsonElement DecodeJwtPayload(string jwt)
    {
        // Simple JWT decoder for testing
        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            throw new ArgumentException("Invalid JWT format");
        }

        var payloadBase64 = parts[1];
        // Add padding if needed
        var padding = (4 - payloadBase64.Length % 4) % 4;
        payloadBase64 += new string('=', padding);

        // Convert base64url to base64
        payloadBase64 = payloadBase64.Replace('-', '+').Replace('_', '/');

        var payloadBytes = Convert.FromBase64String(payloadBase64);
        return JsonSerializer.Deserialize<JsonElement>(payloadBytes);
    }
}
