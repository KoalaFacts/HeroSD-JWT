using HeroSdJwt.Common;
using HeroSdJwt.Core;
using HeroSdJwt.Issuance;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// Contract tests for nested object reconstruction.
/// Validates GetDisclosedObject and GetReconstructibleClaims work correctly.
/// Note: Array element testing is limited by library presentation capabilities - see ARRAY-ELEMENT-LIMITATION.md
/// </summary>
public class ObjectReconstructionContractTests
{
    private static byte[] GenerateSecureTestKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void GetDisclosedObject_WithSingleLevelNesting_ReturnsCorrectObject()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "test-user")
            .WithClaim("address", new { street = "123 Main St", city = "Boston", state = "MA" })
            .MakeSelective("address.street", "address.city")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = sdJwt.ToPresentation("address.street", "address.city");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var address = result.GetDisclosedObject("address");

        // Assert
        Assert.NotNull(address);
        Assert.Equal(JsonValueKind.Object, address.Value.ValueKind);

        Assert.True(address.Value.TryGetProperty("street", out var street));
        Assert.Equal("123 Main St", street.GetString());

        Assert.True(address.Value.TryGetProperty("city", out var city));
        Assert.Equal("Boston", city.GetString());
    }

    [Fact]
    public void GetDisclosedObject_WithMultiLevelNesting_ReturnsNestedStructure()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "test-user")
            .WithClaim("address", new
            {
                street = "123 Main St",
                geo = new { lat = 42.3601, lon = -71.0589 }
            })
            .MakeSelective("address.street", "address.geo.lat", "address.geo.lon")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = sdJwt.ToPresentation("address.street", "address.geo.lat", "address.geo.lon");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var address = result.GetDisclosedObject("address");

        // Assert
        Assert.NotNull(address);
        Assert.True(address.Value.TryGetProperty("street", out var street));
        Assert.Equal("123 Main St", street.GetString());

        Assert.True(address.Value.TryGetProperty("geo", out var geo));
        Assert.Equal(JsonValueKind.Object, geo.ValueKind);

        Assert.True(geo.TryGetProperty("lat", out var lat));
        Assert.Equal(42.3601, lat.GetDouble());

        Assert.True(geo.TryGetProperty("lon", out var lon));
        Assert.Equal(-71.0589, lon.GetDouble());
    }

    [Fact]
    public void GetDisclosedObject_PreservesValueTypes()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "test-user")
            .WithClaim("profile", new
            {
                name = "Alice",
                age = 30,
                verified = true,
                score = 95.5
            })
            .MakeSelective("profile.name", "profile.age", "profile.verified", "profile.score")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = sdJwt.ToPresentation("profile.name", "profile.age", "profile.verified", "profile.score");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var profile = result.GetDisclosedObject("profile");

        // Assert
        Assert.NotNull(profile);

        Assert.True(profile.Value.TryGetProperty("name", out var name));
        Assert.Equal(JsonValueKind.String, name.ValueKind);
        Assert.Equal("Alice", name.GetString());

        Assert.True(profile.Value.TryGetProperty("age", out var age));
        Assert.Equal(JsonValueKind.Number, age.ValueKind);
        Assert.Equal(30, age.GetInt32());

        Assert.True(profile.Value.TryGetProperty("verified", out var verified));
        Assert.Equal(JsonValueKind.True, verified.ValueKind);

        Assert.True(profile.Value.TryGetProperty("score", out var score));
        Assert.Equal(JsonValueKind.Number, score.ValueKind);
        Assert.Equal(95.5, score.GetDouble());
    }

    [Fact]
    public void GetDisclosedObject_WithNonExistentClaim_ReturnsNull()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "test-user")
            .WithClaim("address", new { street = "Main St" })
            .MakeSelective("address.street")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = sdJwt.ToPresentation("address.street");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var nonexistent = result.GetDisclosedObject("profile");

        // Assert
        Assert.Null(nonexistent);
    }

    [Fact]
    public void GetDisclosedObject_WithNullResult_ThrowsArgumentNullException()
    {
        // Arrange
        VerificationResult? result = null;

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            #pragma warning disable CS8604
            result.GetDisclosedObject("address")
            #pragma warning restore CS8604
        );
        Assert.Equal("result", exception.ParamName);
    }

    [Fact]
    public void GetDisclosedObject_WithInvalidResult_ThrowsInvalidOperationException()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var verifier = new SdJwtVerifier();
        var result = verifier.TryVerifyPresentation("invalid.presentation.string", signingKey);

        // Act & Assert
        Assert.False(result.IsValid);
        var exception = Assert.Throws<InvalidOperationException>(() =>
            result.GetDisclosedObject("address")
        );
        Assert.Contains("IsValid", exception.Message);
    }

    [Fact]
    public void GetReconstructibleClaims_IdentifiesObjectClaims()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "test-user")
            .WithClaim("address", new { street = "Main St", city = "Boston" })
            .WithClaim("contact", new { email = "test@example.com", phone = "555-0100" })
            .MakeSelective("address.street", "address.city", "contact.email")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = sdJwt.ToPresentation("address.street", "address.city", "contact.email");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var reconstructible = result.GetReconstructibleClaims();

        // Assert
        Assert.NotNull(reconstructible);
        Assert.Equal(2, reconstructible.Count);

        Assert.True(reconstructible.ContainsKey("address"));
        Assert.Equal(ReconstructibleClaimType.Object, reconstructible["address"]);

        Assert.True(reconstructible.ContainsKey("contact"));
        Assert.Equal(ReconstructibleClaimType.Object, reconstructible["contact"]);
    }

    [Fact]
    public void GetReconstructibleClaims_ExcludesSimpleClaims()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "test-user")
            .WithClaim("email", "alice@example.com")
            .WithClaim("name", "Alice")
            .WithClaim("address", new { street = "Main St" })
            .MakeSelective("email", "name", "address.street")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = sdJwt.ToPresentation("email", "name", "address.street");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var reconstructible = result.GetReconstructibleClaims();

        // Assert
        Assert.NotNull(reconstructible);
        Assert.Single(reconstructible);
        Assert.True(reconstructible.ContainsKey("address"));
        Assert.False(reconstructible.ContainsKey("email"));
        Assert.False(reconstructible.ContainsKey("name"));
    }

    [Fact]
    public void GetReconstructibleClaims_WithNoReconstructibleClaims_ReturnsEmpty()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "test-user")
            .WithClaim("email", "alice@example.com")
            .WithClaim("name", "Alice")
            .MakeSelective("email", "name")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = sdJwt.ToPresentation("email", "name");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var reconstructible = result.GetReconstructibleClaims();

        // Assert
        Assert.NotNull(reconstructible);
        Assert.Empty(reconstructible);
    }

    [Fact]
    public void EndToEnd_CompleteObjectReconstructionWorkflow()
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
                zip = "02101",
                geo = new { lat = 42.3601, lon = -71.0589 }
            })
            .MakeSelective("address.street", "address.city", "address.geo.lat", "address.geo.lon")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        // Act - Holder creates presentation
        var presentation = sdJwt.ToPresentation("address.street", "address.city", "address.geo.lat", "address.geo.lon");

        // Verifier validates and reconstructs
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Discover reconstructible claims
        var reconstructible = result.GetReconstructibleClaims();

        // Reconstruct the object
        var address = result.GetDisclosedObject("address");

        // Assert - Full workflow succeeded
        Assert.True(result.IsValid);

        Assert.Single(reconstructible);
        Assert.Equal(ReconstructibleClaimType.Object, reconstructible["address"]);

        Assert.NotNull(address);
        Assert.Equal("123 Main Street", address.Value.GetProperty("street").GetString());
        Assert.Equal("Boston", address.Value.GetProperty("city").GetString());

        var geo = address.Value.GetProperty("geo");
        Assert.Equal(42.3601, geo.GetProperty("lat").GetDouble());
        Assert.Equal(-71.0589, geo.GetProperty("lon").GetDouble());
    }
}
