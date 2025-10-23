using HeroSdJwt.Common;
using HeroSdJwt.Core;
using HeroSdJwt.Issuance;
using HeroSdJwt.Presentation;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// Contract tests for VerificationResult reconstruction extension methods.
/// These tests define the expected behavior for array and object reconstruction APIs.
/// Written to validate User Stories 1, 2, and 3 acceptance scenarios.
/// </summary>
public class VerificationResultReconstructionContractTests
{
    private static byte[] GenerateSecureTestKey()
    {
        var key = new byte[32]; // 256 bits for HS256
        RandomNumberGenerator.Fill(key);
        return key;
    }

    private static VerificationResult CreateVerificationResultWithArrayElements(byte[] signingKey, params (int index, string value)[] elements)
    {
        var degrees = new string[elements.Max(e => e.index) + 1];
        foreach (var (index, value) in elements)
        {
            degrees[index] = value;
        }

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "test-subject",
            ["degrees"] = degrees
        };

        var selectiveClaims = elements.Select(e => $"degrees[{e.index}]").ToArray();

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(claims, selectiveClaims, signingKey, HashAlgorithm.Sha256);

        // Create presentation revealing the specified array elements
        var presentation = sdJwt.ToPresentation(selectiveClaims);

        var verifier = new SdJwtVerifier();
        return verifier.VerifyPresentation(presentation, signingKey);
    }

    private static VerificationResult CreateVerificationResultWithNestedObject(byte[] signingKey, params (string path, string value)[] properties)
    {
        // Build nested object dynamically
        var address = new Dictionary<string, object>();
        foreach (var (path, value) in properties)
        {
            var parts = path.Split('.');
            if (parts.Length == 2 && parts[0] == "address")
            {
                address[parts[1]] = value;
            }
            else if (parts.Length == 3 && parts[0] == "address")
            {
                if (!address.ContainsKey(parts[1]))
                {
                    address[parts[1]] = new Dictionary<string, object>();
                }
                ((Dictionary<string, object>)address[parts[1]])[parts[2]] = value;
            }
        }

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "test-subject",
            ["address"] = address
        };

        var selectiveClaims = properties.Select(p => p.path).ToArray();

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(claims, selectiveClaims, signingKey, HashAlgorithm.Sha256);

        // Create presentation revealing the specified nested properties
        var presentation = sdJwt.ToPresentation(selectiveClaims);

        var verifier = new SdJwtVerifier();
        return verifier.VerifyPresentation(presentation, signingKey);
    }

    #region User Story 1: GetDisclosedArray Tests (T003-T010)

    [Fact]
    public void GetDisclosedArray_WithNonExistentClaim_ReturnsNull()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithArrayElements(signingKey, (0, "PhD"));

        // Act
        var array = result.GetDisclosedArray("nonexistent");

        // Assert
        Assert.Null(array);
    }

    [Fact]
    public void GetDisclosedArray_WithNoElementsDisclosed_ReturnsEmptyArray()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("degrees", new string[] { })
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation();
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var array = result.GetDisclosedArray("degrees");

        // Assert - should return null because no array element claims exist
        Assert.Null(array);
    }

    [Fact]
    public void GetDisclosedArray_WithConsecutiveIndices_ReturnsSequentialArray()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithArrayElements(signingKey, (0, "PhD"), (1, "MBA"), (2, "BSc"));

        // Act
        var array = result.GetDisclosedArray("degrees");

        // Assert
        Assert.NotNull(array);
        Assert.Equal(JsonValueKind.Array, array.Value.ValueKind);
        Assert.Equal(3, array.Value.GetArrayLength());
        Assert.Equal("PhD", array.Value[0].GetString());
        Assert.Equal("MBA", array.Value[1].GetString());
        Assert.Equal("BSc", array.Value[2].GetString());
    }

    [Fact]
    public void GetDisclosedArray_WithNonSequentialIndices_ReturnsSparseArray()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithArrayElements(signingKey, (0, "PhD"), (3, "MBA"));

        // Act
        var array = result.GetDisclosedArray("degrees");

        // Assert
        Assert.NotNull(array);
        Assert.Equal(JsonValueKind.Array, array.Value.ValueKind);
        Assert.Equal(4, array.Value.GetArrayLength());
        Assert.Equal("PhD", array.Value[0].GetString());
        Assert.Equal(JsonValueKind.Null, array.Value[1].ValueKind);
        Assert.Equal(JsonValueKind.Null, array.Value[2].ValueKind);
        Assert.Equal("MBA", array.Value[3].GetString());
    }

    [Fact]
    public void GetDisclosedArray_PreservesOriginalElementTypes()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("mixed", new object[] { "string", 42, new { name = "object" } })
            .MakeSelective("mixed[0]")
            .MakeSelective("mixed[1]")
            .MakeSelective("mixed[2]")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation("mixed[0]", "mixed[1]", "mixed[2]");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var array = result.GetDisclosedArray("mixed");

        // Assert
        Assert.NotNull(array);
        Assert.Equal(3, array.Value.GetArrayLength());
        Assert.Equal(JsonValueKind.String, array.Value[0].ValueKind);
        Assert.Equal("string", array.Value[0].GetString());
        Assert.Equal(JsonValueKind.Number, array.Value[1].ValueKind);
        Assert.Equal(42, array.Value[1].GetInt32());
        Assert.Equal(JsonValueKind.Object, array.Value[2].ValueKind);
    }

    [Fact]
    public void GetDisclosedArray_WithNullResult_ThrowsArgumentNullException()
    {
        // Arrange
        VerificationResult? result = null;

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
#pragma warning disable CS8604 // Possible null reference argument - intentional for test
            result.GetDisclosedArray("degrees")
#pragma warning restore CS8604
        );
        Assert.Equal("result", exception.ParamName);
    }

    [Fact]
    public void GetDisclosedArray_WithNullClaimName_ThrowsArgumentException()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithArrayElements(signingKey, (0, "PhD"));

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type - intentional for test
            result.GetDisclosedArray(null)
#pragma warning restore CS8625
        );
        Assert.Equal("claimName", exception.ParamName);
    }

    [Fact]
    public void GetDisclosedArray_WithInvalidResult_ThrowsInvalidOperationException()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var invalidPresentation = "invalid.presentation.string";
        var verifier = new SdJwtVerifier();
        var result = verifier.TryVerifyPresentation(invalidPresentation, signingKey);

        // Act & Assert
        Assert.False(result.IsValid);
        var exception = Assert.Throws<InvalidOperationException>(() =>
            result.GetDisclosedArray("degrees")
        );
        Assert.Contains("IsValid", exception.Message);
    }

    #endregion

    #region User Story 2: GetDisclosedObject Tests (T026-T034)

    [Fact]
    public void GetDisclosedObject_WithNonExistentClaim_ReturnsNull()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithNestedObject(signingKey, ("address.street", "Main St"));

        // Act
        var obj = result.GetDisclosedObject("nonexistent");

        // Assert
        Assert.Null(obj);
    }

    [Fact]
    public void GetDisclosedObject_WithNoPropertiesDisclosed_ReturnsNull()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("address", new { })
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation();
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var obj = result.GetDisclosedObject("address");

        // Assert - should return null because no nested property claims exist
        Assert.Null(obj);
    }

    [Fact]
    public void GetDisclosedObject_WithSingleLevelNesting_ReturnsFlatObject()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithNestedObject(signingKey,
            ("address.street", "123 Main St"),
            ("address.city", "Boston"));

        // Act
        var obj = result.GetDisclosedObject("address");

        // Assert
        Assert.NotNull(obj);
        Assert.Equal(JsonValueKind.Object, obj.Value.ValueKind);
        Assert.True(obj.Value.TryGetProperty("street", out var street));
        Assert.Equal("123 Main St", street.GetString());
        Assert.True(obj.Value.TryGetProperty("city", out var city));
        Assert.Equal("Boston", city.GetString());
    }

    [Fact]
    public void GetDisclosedObject_WithMultiLevelPaths_ReturnsNestedObject()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithNestedObject(signingKey,
            ("address.geo.lat", "42.3601"),
            ("address.geo.lon", "-71.0589"));

        // Act
        var obj = result.GetDisclosedObject("address");

        // Assert
        Assert.NotNull(obj);
        Assert.Equal(JsonValueKind.Object, obj.Value.ValueKind);
        Assert.True(obj.Value.TryGetProperty("geo", out var geo));
        Assert.Equal(JsonValueKind.Object, geo.ValueKind);
        Assert.True(geo.TryGetProperty("lat", out var lat));
        Assert.Equal("42.3601", lat.GetString());
        Assert.True(geo.TryGetProperty("lon", out var lon));
        Assert.Equal("-71.0589", lon.GetString());
    }

    [Fact]
    public void GetDisclosedObject_WithMixedNestingDepths_HandlesCorrectly()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithNestedObject(signingKey,
            ("address.street", "Main St"),
            ("address.geo.lat", "42.3601"));

        // Act
        var obj = result.GetDisclosedObject("address");

        // Assert
        Assert.NotNull(obj);
        Assert.True(obj.Value.TryGetProperty("street", out var street));
        Assert.Equal("Main St", street.GetString());
        Assert.True(obj.Value.TryGetProperty("geo", out var geo));
        Assert.True(geo.TryGetProperty("lat", out var lat));
        Assert.Equal("42.3601", lat.GetString());
    }

    [Fact]
    public void GetDisclosedObject_PreservesOriginalValueTypes()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("data", new { str = "text", num = 42, flag = true })
            .MakeSelective("data.str")
            .MakeSelective("data.num")
            .MakeSelective("data.flag")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation("data.str", "data.num", "data.flag");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var obj = result.GetDisclosedObject("data");

        // Assert
        Assert.NotNull(obj);
        Assert.True(obj.Value.TryGetProperty("str", out var str));
        Assert.Equal(JsonValueKind.String, str.ValueKind);
        Assert.True(obj.Value.TryGetProperty("num", out var num));
        Assert.Equal(JsonValueKind.Number, num.ValueKind);
        Assert.True(obj.Value.TryGetProperty("flag", out var flag));
        Assert.Equal(JsonValueKind.True, flag.ValueKind);
    }

    [Fact]
    public void GetDisclosedObject_WithNullResult_ThrowsArgumentNullException()
    {
        // Arrange
        VerificationResult? result = null;

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
#pragma warning disable CS8604 // Possible null reference argument - intentional for test
            result.GetDisclosedObject("address")
#pragma warning restore CS8604
        );
        Assert.Equal("result", exception.ParamName);
    }

    [Fact]
    public void GetDisclosedObject_WithNullClaimName_ThrowsArgumentException()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithNestedObject(signingKey, ("address.street", "Main St"));

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type - intentional for test
            result.GetDisclosedObject(null)
#pragma warning restore CS8625
        );
        Assert.Equal("claimName", exception.ParamName);
    }

    [Fact]
    public void GetDisclosedObject_WithInvalidResult_ThrowsInvalidOperationException()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var invalidPresentation = "invalid.presentation.string";
        var verifier = new SdJwtVerifier();
        var result = verifier.TryVerifyPresentation(invalidPresentation, signingKey);

        // Act & Assert
        Assert.False(result.IsValid);
        var exception = Assert.Throws<InvalidOperationException>(() =>
            result.GetDisclosedObject("address")
        );
        Assert.Contains("IsValid", exception.Message);
    }

    #endregion

    #region User Story 3: GetReconstructibleClaims Tests (T050-T056)

    [Fact]
    public void GetReconstructibleClaims_WithNoReconstructibleClaims_ReturnsEmptyDictionary()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("email", "alice@example.com")
            .MakeSelective("email")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation("email");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var reconstructible = result.GetReconstructibleClaims();

        // Assert
        Assert.NotNull(reconstructible);
        Assert.Empty(reconstructible);
    }

    [Fact]
    public void GetReconstructibleClaims_IdentifiesArrayClaimsCorrectly()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithArrayElements(signingKey, (0, "PhD"), (1, "MBA"));

        // Act
        var reconstructible = result.GetReconstructibleClaims();

        // Assert
        Assert.NotNull(reconstructible);
        Assert.Single(reconstructible);
        Assert.True(reconstructible.ContainsKey("degrees"));
        Assert.Equal(ReconstructibleClaimType.Array, reconstructible["degrees"]);
    }

    [Fact]
    public void GetReconstructibleClaims_IdentifiesObjectClaimsCorrectly()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var result = CreateVerificationResultWithNestedObject(signingKey,
            ("address.street", "Main St"),
            ("address.city", "Boston"));

        // Act
        var reconstructible = result.GetReconstructibleClaims();

        // Assert
        Assert.NotNull(reconstructible);
        Assert.Single(reconstructible);
        Assert.True(reconstructible.ContainsKey("address"));
        Assert.Equal(ReconstructibleClaimType.Object, reconstructible["address"]);
    }

    [Fact]
    public void GetReconstructibleClaims_HandlesMixedTypesCorrectly()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("email", "alice@example.com")
            .WithClaim("degrees", new[] { "PhD", "MBA" })
            .WithClaim("address", new { street = "Main St", city = "Boston" })
            .MakeSelective("email")
            .MakeSelective("degrees[0]")
            .MakeSelective("address.street")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation("email", "degrees[0]", "address.street");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var reconstructible = result.GetReconstructibleClaims();

        // Assert
        Assert.NotNull(reconstructible);
        Assert.Equal(2, reconstructible.Count);
        Assert.True(reconstructible.ContainsKey("degrees"));
        Assert.Equal(ReconstructibleClaimType.Array, reconstructible["degrees"]);
        Assert.True(reconstructible.ContainsKey("address"));
        Assert.Equal(ReconstructibleClaimType.Object, reconstructible["address"]);
        Assert.False(reconstructible.ContainsKey("email")); // Simple claim excluded
    }

    [Fact]
    public void GetReconstructibleClaims_ExcludesSimpleClaims()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "test")
            .WithClaim("email", "alice@example.com")
            .WithClaim("name", "Alice")
            .MakeSelective("email")
            .MakeSelective("name")
            .SignWithHmac(signingKey)
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .Build();

        var presentation = builder.ToPresentation("email", "name");
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, signingKey);

        // Act
        var reconstructible = result.GetReconstructibleClaims();

        // Assert
        Assert.NotNull(reconstructible);
        Assert.Empty(reconstructible);
    }

    [Fact]
    public void GetReconstructibleClaims_WithNullResult_ThrowsArgumentNullException()
    {
        // Arrange
        VerificationResult? result = null;

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
#pragma warning disable CS8604 // Possible null reference argument - intentional for test
            result.GetReconstructibleClaims()
#pragma warning restore CS8604
        );
        Assert.Equal("result", exception.ParamName);
    }

    [Fact]
    public void GetReconstructibleClaims_WithInvalidResult_ThrowsInvalidOperationException()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var invalidPresentation = "invalid.presentation.string";
        var verifier = new SdJwtVerifier();
        var result = verifier.TryVerifyPresentation(invalidPresentation, signingKey);

        // Act & Assert
        Assert.False(result.IsValid);
        var exception = Assert.Throws<InvalidOperationException>(() =>
            result.GetReconstructibleClaims()
        );
        Assert.Contains("IsValid", exception.Message);
    }

    #endregion
}
