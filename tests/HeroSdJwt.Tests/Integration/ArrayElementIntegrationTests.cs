using HeroSdJwt.Tests;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using Base64UrlEncoder = HeroSdJwt.Encoding.Base64UrlEncoder;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// End-to-end integration tests for array element selective disclosure.
/// Tests the full flow: issuer creates SD-JWT with array elements -> verifier validates and extracts claims.
/// </summary>
public class ArrayElementIntegrationTests
{
    private readonly byte[] signingKey;
    private readonly SdJwtIssuer issuer;
    private readonly SdJwtVerifier verifier;

    public ArrayElementIntegrationTests()
    {
        // Generate a signing key for tests
        this.signingKey = new byte[32];
        RandomNumberGenerator.Fill(this.signingKey);

        this.issuer = TestHelpers.CreateIssuer();
        this.verifier = TestHelpers.CreateVerifier();
    }

    [Fact]
    public void EndToEnd_ArrayWithSelectiveElements_WorksCorrectly()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["degrees"] = new[] { "BS", "MS", "PhD" }
        };

        // Make degrees[1] and degrees[2] selectively disclosable
        var selectiveClaims = new[] { "degrees[1]", "degrees[2]" };

        // Act - Issue SD-JWT
        var sdJwt = issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            signingKey,
            HashAlgorithm.Sha256);

        // Assert - Check JWT structure
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
        Assert.Equal(2, sdJwt.Disclosures.Count); // Two array elements

        // Decode JWT payload to verify array structure
        var jwtParts = sdJwt.Jwt.Split('.');
        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        // Check degrees array has placeholders
        Assert.True(payload.TryGetProperty("degrees", out var degreesArray));
        Assert.Equal(JsonValueKind.Array, degreesArray.ValueKind);
        Assert.Equal(3, degreesArray.GetArrayLength());

        // Index 0 should be plaintext "BS"
        Assert.Equal("BS", degreesArray[0].GetString());

        // Index 1 should be a placeholder object
        Assert.Equal(JsonValueKind.Object, degreesArray[1].ValueKind);
        Assert.True(degreesArray[1].TryGetProperty("...", out var digest1));
        Assert.NotEmpty(digest1.GetString()!);

        // Index 2 should be a placeholder object
        Assert.Equal(JsonValueKind.Object, degreesArray[2].ValueKind);
        Assert.True(degreesArray[2].TryGetProperty("...", out var digest2));
        Assert.NotEmpty(digest2.GetString()!);

        // Verify _sd array contains digests
        Assert.True(payload.TryGetProperty("_sd", out var sdArray));
        Assert.Equal(2, sdArray.GetArrayLength());
    }

    [Fact]
    public void EndToEnd_MixedArrayElements_OnlySomeSelective()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user456",
            ["certifications"] = new[] { "AWS", "Azure", "GCP", "Kubernetes" }
        };

        // Only make certifications[1] and certifications[3] selectively disclosable
        var selectiveClaims = new[] { "certifications[1]", "certifications[3]" };

        // Act
        var sdJwt = issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            signingKey,
            HashAlgorithm.Sha256);

        // Assert
        var jwtParts = sdJwt.Jwt.Split('.');
        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        var certArray = payload.GetProperty("certifications");
        Assert.Equal(4, certArray.GetArrayLength());

        // Index 0: plaintext
        Assert.Equal("AWS", certArray[0].GetString());

        // Index 1: placeholder
        Assert.Equal(JsonValueKind.Object, certArray[1].ValueKind);

        // Index 2: plaintext
        Assert.Equal("GCP", certArray[2].GetString());

        // Index 3: placeholder
        Assert.Equal(JsonValueKind.Object, certArray[3].ValueKind);
    }

    [Fact]
    public void EndToEnd_ArrayWithComplexObjects_SelectiveElements()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user789",
            ["education"] = new[]
            {
                new { institution = "MIT", year = 2010, degree = "BS" },
                new { institution = "Stanford", year = 2012, degree = "MS" },
                new { institution = "Berkeley", year = 2016, degree = "PhD" }
            }
        };

        // Make education[1] and education[2] selectively disclosable
        var selectiveClaims = new[] { "education[1]", "education[2]" };

        // Act
        var sdJwt = issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            signingKey,
            HashAlgorithm.Sha256);

        // Assert
        var jwtParts = sdJwt.Jwt.Split('.');
        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        var eduArray = payload.GetProperty("education");
        Assert.Equal(3, eduArray.GetArrayLength());

        // Index 0: plaintext object
        Assert.Equal(JsonValueKind.Object, eduArray[0].ValueKind);
        Assert.Equal("MIT", eduArray[0].GetProperty("institution").GetString());

        // Index 1 and 2: placeholders
        Assert.True(eduArray[1].TryGetProperty("...", out _));
        Assert.True(eduArray[2].TryGetProperty("...", out _));
    }

    [Fact]
    public void CreateSdJwt_ArrayIndexOutOfBounds_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["items"] = new[] { "A", "B", "C" }
        };

        var selectiveClaims = new[] { "items[5]" }; // Out of bounds

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            issuer.CreateSdJwt(claims, selectiveClaims, signingKey, HashAlgorithm.Sha256));

        Assert.Contains("out of bounds", exception.Message);
        Assert.Contains("items", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_NonArrayClaimWithArraySyntax_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["email"] = "test@example.com" // Not an array
        };

        var selectiveClaims = new[] { "email[0]" }; // Trying to use array syntax

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            issuer.CreateSdJwt(claims, selectiveClaims, signingKey, HashAlgorithm.Sha256));

        Assert.Contains("not an array", exception.Message);
        Assert.Contains("email", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_CombineSimpleAndArrayClaims_WorksCorrectly()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user999",
            ["email"] = "test@example.com",
            ["phone"] = "+1234567890",
            ["roles"] = new[] { "admin", "user", "guest" }
        };

        // Mix simple claims and array elements
        var selectiveClaims = new[] { "email", "roles[0]", "roles[2]" };

        // Act
        var sdJwt = issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            signingKey,
            HashAlgorithm.Sha256);

        // Assert
        Assert.Equal(3, sdJwt.Disclosures.Count); // email + roles[0] + roles[2]

        var jwtParts = sdJwt.Jwt.Split('.');
        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        // email should not be in payload (selectively disclosable)
        Assert.False(payload.TryGetProperty("email", out _));

        // sub and phone should be in payload (not selectively disclosable)
        Assert.Equal("user999", payload.GetProperty("sub").GetString());
        Assert.Equal("+1234567890", payload.GetProperty("phone").GetString());

        // roles should have mixed structure
        var rolesArray = payload.GetProperty("roles");
        Assert.True(rolesArray[0].TryGetProperty("...", out _)); // Placeholder
        Assert.Equal("user", rolesArray[1].GetString()); // Plaintext
        Assert.True(rolesArray[2].TryGetProperty("...", out _)); // Placeholder
    }

    [Fact]
    public void EndToEnd_EmptyArray_WorksCorrectly()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user000",
            ["items"] = new string[0] // Empty array
        };

        // Act - No selective claims for the empty array
        var sdJwt = issuer.CreateSdJwt(
            claims,
            Array.Empty<string>(),
            signingKey,
            HashAlgorithm.Sha256);

        // Assert
        var jwtParts = sdJwt.Jwt.Split('.');
        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        var itemsArray = payload.GetProperty("items");
        Assert.Equal(0, itemsArray.GetArrayLength());
    }
}
