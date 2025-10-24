using HeroSdJwt.Common;
using HeroSdJwt.Core;
using HeroSdJwt.Issuance;
using HeroSdJwt.Presentation;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Unit tests for object reconstruction logic.
/// Tests edge cases and specific scenarios for GetDisclosedObject.
/// </summary>
public class ObjectReconstructionTests
{
    private static byte[] GenerateSecureTestKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void ObjectReconstruction_HandlesDeeplyNestedClaims()
    {
        // Arrange - 10 levels deep
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

        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("data", deepObject)
            .MakeSelective("data.level1.level2.level3.level4.level5.level6.level7.level8.level9.level10")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation("data.level1.level2.level3.level4.level5.level6.level7.level8.level9.level10");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var obj = result.GetDisclosedObject("data");

        // Assert - navigate all 10 levels
        Assert.NotNull(obj);
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
        Assert.True(current.TryGetProperty("level10", out var finalValue));
        Assert.Equal("deep value", finalValue.GetString());
    }

    [Fact]
    public void ObjectReconstruction_IsIdempotent()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("address", new { street = "Main St", city = "Boston" })
            .MakeSelective("address.street")
            .MakeSelective("address.city")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation("address.street", "address.city");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act - call multiple times
        var obj1 = result.GetDisclosedObject("address");
        var obj2 = result.GetDisclosedObject("address");
        var obj3 = result.GetDisclosedObject("address");

        // Assert - all calls return same structure
        Assert.NotNull(obj1);
        Assert.NotNull(obj2);
        Assert.NotNull(obj3);

        Assert.Equal(obj1.Value.GetProperty("street").GetString(), obj2.Value.GetProperty("street").GetString());
        Assert.Equal(obj1.Value.GetProperty("street").GetString(), obj3.Value.GetProperty("street").GetString());
    }

    [Fact]
    public void ObjectReconstruction_HandlesPropertiesDisclosedOutOfOrder()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("person", new
            {
                name = "Alice",
                age = 30,
                email = "alice@example.com",
                city = "Boston"
            })
            .MakeSelective("person.city")
            .MakeSelective("person.name")
            .MakeSelective("person.email")
            .MakeSelective("person.age")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        // Present in different order than defined
        var presentation = builder.ToPresentation("person.city", "person.name", "person.email", "person.age");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var obj = result.GetDisclosedObject("person");

        // Assert - all properties should be present regardless of order
        Assert.NotNull(obj);
        Assert.True(obj.Value.TryGetProperty("name", out var name));
        Assert.Equal("Alice", name.GetString());
        Assert.True(obj.Value.TryGetProperty("age", out var age));
        Assert.Equal(30, age.GetInt32());
        Assert.True(obj.Value.TryGetProperty("email", out var email));
        Assert.Equal("alice@example.com", email.GetString());
        Assert.True(obj.Value.TryGetProperty("city", out var city));
        Assert.Equal("Boston", city.GetString());
    }
}
