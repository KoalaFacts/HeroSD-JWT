using HeroSdJwt.Tests;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using Xunit;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Unit tests for claim discovery logic.
/// Tests edge cases and specific scenarios for GetReconstructibleClaims.
/// </summary>
public class ClaimDiscoveryTests
{
    private static byte[] GenerateSecureTestKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void Discovery_IsIdempotent()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("degrees", new[] { "PhD", "MBA" })
            .WithClaim("address", new { street = "Main St" })
            .MakeSelective("degrees[0]")
            .MakeSelective("address.street")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation("degrees[0]", "address.street");
        var verifier = TestHelpers.CreateVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act - call multiple times
        var dict1 = result.GetReconstructibleClaims();
        var dict2 = result.GetReconstructibleClaims();
        var dict3 = result.GetReconstructibleClaims();

        // Assert - all calls return same structure
        Assert.Equal(dict1.Count, dict2.Count);
        Assert.Equal(dict1.Count, dict3.Count);

        Assert.Equal(dict1["degrees"], dict2["degrees"]);
        Assert.Equal(dict1["address"], dict2["address"]);
    }

    [Fact]
    public void Discovery_CorrectlyCategorizesMultipleArraysAndObjects()
    {
        // Arrange - multiple arrays and objects
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("degrees", new[] { "PhD" })
            .WithClaim("certifications", new[] { "AWS", "Azure" })
            .WithClaim("address", new { street = "Main St" })
            .WithClaim("contact", new { email = "test@example.com" })
            .MakeSelective("degrees[0]")
            .MakeSelective("certifications[0]")
            .MakeSelective("certifications[1]")
            .MakeSelective("address.street")
            .MakeSelective("contact.email")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation("degrees[0]", "certifications[0]", "certifications[1]", "address.street", "contact.email");
        var verifier = TestHelpers.CreateVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var reconstructible = result.GetReconstructibleClaims();

        // Assert
        Assert.Equal(4, reconstructible.Count);
        Assert.Equal(ReconstructibleClaimType.Array, reconstructible["degrees"]);
        Assert.Equal(ReconstructibleClaimType.Array, reconstructible["certifications"]);
        Assert.Equal(ReconstructibleClaimType.Object, reconstructible["address"]);
        Assert.Equal(ReconstructibleClaimType.Object, reconstructible["contact"]);
    }
}
