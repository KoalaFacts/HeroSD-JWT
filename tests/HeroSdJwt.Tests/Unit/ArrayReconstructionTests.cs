using HeroSdJwt.Tests;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Unit tests for array reconstruction logic.
/// Tests edge cases and specific scenarios for GetDisclosedArray.
/// </summary>
public class ArrayReconstructionTests
{
    private static byte[] GenerateSecureTestKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    private static VerificationResult CreateVerificationResultWithArrayElements(byte[] signingKey, params (int index, string value)[] elements)
    {
        var maxIndex = elements.Max(e => e.index);
        var array = new string[maxIndex + 1];
        foreach (var (index, value) in elements)
        {
            array[index] = value;
        }

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "test-subject",
            ["degrees"] = array
        };

        var selectiveClaims = elements.Select(e => $"degrees[{e.index}]").ToArray();

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt = issuer.CreateSdJwt(claims, selectiveClaims, signingKey, HashAlgorithm.Sha256);

        // Create presentation revealing the specified array elements
        var presentation = sdJwt.ToPresentation(selectiveClaims);

        var verifier = TestHelpers.CreateVerifier();
        return verifier.VerifyPresentation(presentation, signingKey);
    }

    [Fact]
    public void ArrayReconstruction_HandlesLargeSparseArrays()
    {
        // Arrange - sparse array with indices 0, 50, 100
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithArrayElements(signingKey,
            (0, "First"),
            (50, "Middle"),
            (100, "Last"));

        // Act
        var array = result.GetDisclosedArray("degrees");

        // Assert
        Assert.NotNull(array);
        Assert.Equal(101, array.Value.GetArrayLength());
        Assert.Equal("First", array.Value[0].GetString());
        Assert.Equal("Middle", array.Value[50].GetString());
        Assert.Equal("Last", array.Value[100].GetString());

        // Verify all intermediate elements are null
        for (int i = 1; i < 50; i++)
        {
            Assert.Equal(JsonValueKind.Null, array.Value[i].ValueKind);
        }
    }

    [Fact]
    public void ArrayReconstruction_HandlesOutOfOrderIndices()
    {
        // Arrange - indices disclosed in reverse order
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("items", new[] { "A", "B", "C", "D" })
            .MakeSelective("items[3]")
            .MakeSelective("items[1]")
            .MakeSelective("items[2]")
            .MakeSelective("items[0]")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        // Present in out-of-order sequence
        var presentation = builder.ToPresentation("items[3]", "items[1]", "items[2]", "items[0]");
        var verifier = TestHelpers.CreateVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var array = result.GetDisclosedArray("items");

        // Assert - should still be in correct index order
        Assert.NotNull(array);
        Assert.Equal(4, array.Value.GetArrayLength());
        Assert.Equal("A", array.Value[0].GetString());
        Assert.Equal("B", array.Value[1].GetString());
        Assert.Equal("C", array.Value[2].GetString());
        Assert.Equal("D", array.Value[3].GetString());
    }

    [Fact]
    public void ArrayReconstruction_IsIdempotent()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithArrayElements(signingKey,
            (0, "PhD"),
            (2, "MBA"));

        // Act - call multiple times
        var array1 = result.GetDisclosedArray("degrees");
        var array2 = result.GetDisclosedArray("degrees");
        var array3 = result.GetDisclosedArray("degrees");

        // Assert - all calls return same structure
        Assert.NotNull(array1);
        Assert.NotNull(array2);
        Assert.NotNull(array3);

        Assert.Equal(array1.Value.GetArrayLength(), array2.Value.GetArrayLength());
        Assert.Equal(array1.Value.GetArrayLength(), array3.Value.GetArrayLength());

        Assert.Equal(array1.Value[0].GetString(), array2.Value[0].GetString());
        Assert.Equal(array1.Value[0].GetString(), array3.Value[0].GetString());
    }
}
