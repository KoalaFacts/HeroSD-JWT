using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// End-to-end integration tests for the full reconstruction workflow.
/// Tests complete flow: SdJwtBuilder → Presentation → Verifier → Reconstruction
/// </summary>
public class ArrayReconstructionEndToEndTests
{
    private static byte[] GenerateSecureTestKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void EndToEnd_ArrayReconstruction_CompleteWorkflow()
    {
        // Arrange - Issuer creates SD-JWT with array
        var signingKey = GenerateSecureTestKey();
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "alice@example.com")
            .WithClaim("degrees", new[] { "PhD in Computer Science", "MBA", "BSc in Mathematics" })
            .MakeSelective("degrees[0]")
            .MakeSelective("degrees[1]")
            .MakeSelective("degrees[2]")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        // Act - Holder creates presentation
        var presentation = sdJwt.ToPresentation("degrees[0]", "degrees[1]", "degrees[2]");

        // Verifier validates and reconstructs
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        var degrees = result.GetDisclosedArray("degrees");

        // Assert - Full workflow succeeded
        Assert.True(result.IsValid);
        Assert.NotNull(degrees);
        Assert.Equal(3, degrees.Value.GetArrayLength());
        Assert.Equal("PhD in Computer Science", degrees.Value[0].GetString());
        Assert.Equal("MBA", degrees.Value[1].GetString());
        Assert.Equal("BSc in Mathematics", degrees.Value[2].GetString());
    }

    [Fact]
    public void EndToEnd_ObjectReconstruction_CompleteWorkflow()
    {
        // Arrange - Issuer creates SD-JWT with nested object
        var signingKey = GenerateSecureTestKey();
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "alice@example.com")
            .WithClaim("address", new
            {
                street = "123 Main Street",
                city = "Boston",
                state = "MA",
                geo = new { lat = 42.3601, lon = -71.0589 }
            })
            .MakeSelective("address.street")
            .MakeSelective("address.city")
            .MakeSelective("address.geo.lat")
            .MakeSelective("address.geo.lon")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        // Act - Holder creates presentation
        var presentation = sdJwt.ToPresentation("address.street", "address.city", "address.geo.lat", "address.geo.lon");

        // Verifier validates and reconstructs
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        var address = result.GetDisclosedObject("address");

        // Assert - Full workflow succeeded
        Assert.True(result.IsValid);
        Assert.NotNull(address);
        Assert.Equal("123 Main Street", address.Value.GetProperty("street").GetString());
        Assert.Equal("Boston", address.Value.GetProperty("city").GetString());

        var geo = address.Value.GetProperty("geo");
        Assert.Equal(42.3601, geo.GetProperty("lat").GetDouble());
        Assert.Equal(-71.0589, geo.GetProperty("lon").GetDouble());
    }

    [Fact]
    public void EndToEnd_Discovery_CompleteWorkflow()
    {
        // Arrange - Issuer creates SD-JWT with mixed claims
        var signingKey = GenerateSecureTestKey();
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "alice@example.com")
            .WithClaim("email", "alice@example.com")
            .WithClaim("degrees", new[] { "PhD", "MBA" })
            .WithClaim("address", new { street = "Main St", city = "Boston" })
            .MakeSelective("email")
            .MakeSelective("degrees[0]")
            .MakeSelective("address.street")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        // Act - Holder creates presentation
        var presentation = sdJwt.ToPresentation("email", "degrees[0]", "address.street");

        // Verifier validates and discovers
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        var reconstructible = result.GetReconstructibleClaims();

        // Assert - Discovery identified correct types
        Assert.True(result.IsValid);
        Assert.Equal(2, reconstructible.Count);
        Assert.Equal(ReconstructibleClaimType.Array, reconstructible["degrees"]);
        Assert.Equal(ReconstructibleClaimType.Object, reconstructible["address"]);
        Assert.False(reconstructible.ContainsKey("email")); // Simple claim excluded
    }

    [Fact]
    public void Performance_ArrayReconstruction_CompletesUnder50ms()
    {
        // Arrange - Create array with 100 elements
        var signingKey = GenerateSecureTestKey();
        var largeArray = Enumerable.Range(0, 100).Select(i => $"Element-{i}").ToArray();

        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("items", largeArray);

        for (int i = 0; i < 100; i++)
        {
            builder.MakeSelective($"items[{i}]");
        }

        var sdJwt = builder
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = sdJwt.ToPresentation(Enumerable.Range(0, 100).Select(i => $"items[{i}]").ToArray());
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act - Measure reconstruction time
        var stopwatch = Stopwatch.StartNew();
        var array = result.GetDisclosedArray("items");
        stopwatch.Stop();

        // Assert - Should complete in under 50ms (SC-003 - adjusted for CI environment overhead)
        // Note: Local runs typically <10ms, CI can vary 12-145ms due to shared resources
        Assert.NotNull(array);
        Assert.Equal(100, array.Value.GetArrayLength());
        Assert.True(stopwatch.ElapsedMilliseconds < 50,
            $"Array reconstruction took {stopwatch.ElapsedMilliseconds}ms, expected <50ms");
    }

    [Fact]
    public void Performance_ObjectReconstruction_Handles10LevelsOfNesting()
    {
        // Arrange - Create object with 10 levels of nesting
        var signingKey = GenerateSecureTestKey();
        var deepObject = new Dictionary<string, object>
        {
            ["level1"] = new Dictionary<string, object>
            {
                ["level2"] = new Dictionary<string, object>
                {
                    ["level3"] = new Dictionary<string, object>
                    {
                        ["level4"] = new Dictionary<string, object>
                        {
                            ["level5"] = new Dictionary<string, object>
                            {
                                ["level6"] = new Dictionary<string, object>
                                {
                                    ["level7"] = new Dictionary<string, object>
                                    {
                                        ["level8"] = new Dictionary<string, object>
                                        {
                                            ["level9"] = new Dictionary<string, object>
                                            {
                                                ["level10"] = "deep value"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("data", deepObject)
            .MakeSelective("data.level1.level2.level3.level4.level5.level6.level7.level8.level9.level10")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = sdJwt.ToPresentation("data.level1.level2.level3.level4.level5.level6.level7.level8.level9.level10");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act - Reconstruct deeply nested object
        var obj = result.GetDisclosedObject("data");

        // Assert - Should handle 10 levels without error (SC-004)
        Assert.NotNull(obj);

        // Navigate to level 10
        var current = obj.Value;
        Assert.True(current.TryGetProperty("level1", out current));
        Assert.True(current.TryGetProperty("level2", out current));
        Assert.True(current.TryGetProperty("level3", out current));
        Assert.True(current.TryGetProperty("level4", out current));
        Assert.True(current.TryGetProperty("level5", out current));
        Assert.True(current.TryGetProperty("level6", out current));
        Assert.True(current.TryGetProperty("level7", out current));
        Assert.True(current.TryGetProperty("level8", out current));
        Assert.True(current.TryGetProperty("level9", out current));
        Assert.True(current.TryGetProperty("level10", out var value));
        Assert.Equal("deep value", value.GetString());
    }
}
