using HeroSdJwt.Common;
using HeroSdJwt.Issuance;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// End-to-end integration tests for nested selective disclosure.
/// Tests the ability to have _sd arrays within nested objects.
/// </summary>
public class NestedDisclosureIntegrationTests
{
    private readonly byte[] _signingKey;
    private readonly SdJwtIssuer _issuer;

    public NestedDisclosureIntegrationTests()
    {
        _signingKey = new byte[32];
        RandomNumberGenerator.Fill(_signingKey);
        _issuer = new SdJwtIssuer();
    }

    [Fact]
    public void EndToEnd_NestedProperty_CreatesObjectWithSdArray()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["address"] = new Dictionary<string, object>
            {
                { "street", "123 Main St" },
                { "city", "Springfield" },
                { "zipcode", "12345" }
            }
        };

        // Make address.zipcode selectively disclosable
        var selectiveClaims = new[] { "address.zipcode" };

        // Act
        var sdJwt = _issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            _signingKey,
            HashAlgorithm.Sha256);

        // Assert
        Assert.NotNull(sdJwt);
        Assert.Single(sdJwt.Disclosures); // One nested disclosure

        // Decode JWT payload
        var jwtParts = sdJwt.Jwt.Split('.');
        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        // Check address object exists and has _sd array
        Assert.True(payload.TryGetProperty("address", out var addressObj));
        Assert.Equal(JsonValueKind.Object, addressObj.ValueKind);

        // Address should have street and city (not selective)
        Assert.True(addressObj.TryGetProperty("street", out var street));
        Assert.Equal("123 Main St", street.GetString());

        Assert.True(addressObj.TryGetProperty("city", out var city));
        Assert.Equal("Springfield", city.GetString());

        // Address should have _sd array with zipcode digest
        Assert.True(addressObj.TryGetProperty("_sd", out var sdArray));
        Assert.Equal(JsonValueKind.Array, sdArray.ValueKind);
        Assert.Single(sdArray.EnumerateArray());

        // Zipcode should NOT be in the address object
        Assert.False(addressObj.TryGetProperty("zipcode", out _));
    }

    [Fact]
    public void EndToEnd_MultipleNestedProperties_CreatesCorrectStructure()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-456",
            ["address"] = new Dictionary<string, object>
            {
                { "street", "456 Oak Ave" },
                { "city", "Portland" },
                { "state", "OR" },
                { "zipcode", "97201" }
            }
        };

        // Make both city and zipcode selectively disclosable
        var selectiveClaims = new[] { "address.city", "address.zipcode" };

        // Act
        var sdJwt = _issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            _signingKey,
            HashAlgorithm.Sha256);

        // Assert
        Assert.Equal(2, sdJwt.Disclosures.Count); // Two nested disclosures

        var jwtParts = sdJwt.Jwt.Split('.');
        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        var addressObj = payload.GetProperty("address");

        // Should have street and state (not selective)
        Assert.Equal("456 Oak Ave", addressObj.GetProperty("street").GetString());
        Assert.Equal("OR", addressObj.GetProperty("state").GetString());

        // Should have _sd array with 2 digests
        var sdArray = addressObj.GetProperty("_sd");
        Assert.Equal(2, sdArray.GetArrayLength());

        // City and zipcode should NOT be in the object
        Assert.False(addressObj.TryGetProperty("city", out _));
        Assert.False(addressObj.TryGetProperty("zipcode", out _));
    }

    [Fact]
    public void EndToEnd_MixedTopLevelAndNested_BothWork()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-789",
            ["email"] = "alice@example.com",
            ["phone"] = "+1234567890",
            ["address"] = new Dictionary<string, object>
            {
                { "street", "789 Pine Rd" },
                { "city", "Seattle" }
            }
        };

        // Mix top-level and nested selective claims
        var selectiveClaims = new[] { "email", "address.city" };

        // Act
        var sdJwt = _issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            _signingKey,
            HashAlgorithm.Sha256);

        // Assert
        Assert.Equal(2, sdJwt.Disclosures.Count);

        var jwtParts = sdJwt.Jwt.Split('.');
        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        // Email should not be in top-level payload
        Assert.False(payload.TryGetProperty("email", out _));

        // Top-level _sd should exist with email digest
        Assert.True(payload.TryGetProperty("_sd", out var topLevelSd));
        Assert.Single(topLevelSd.EnumerateArray());

        // Address object should exist
        var addressObj = payload.GetProperty("address");
        Assert.Equal("789 Pine Rd", addressObj.GetProperty("street").GetString());

        // Address should have its own _sd array with city digest
        var nestedSd = addressObj.GetProperty("_sd");
        Assert.Single(nestedSd.EnumerateArray());

        // City should not be in address object
        Assert.False(addressObj.TryGetProperty("city", out _));
    }

    [Fact]
    public void CreateSdJwt_NestedPropertyOnNonObject_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["email"] = "test@example.com" // Not an object
        };

        var selectiveClaims = new[] { "email.domain" }; // Trying to use nested syntax

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, selectiveClaims, _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("not an object", exception.Message);
        Assert.Contains("email", exception.Message);
    }

    [Fact]
    public void EndToEnd_AllNestedPropertiesSelective_ObjectHasOnlySdArray()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-999",
            ["credentials"] = new Dictionary<string, object>
            {
                { "username", "alice" },
                { "password_hash", "hash123" }
            }
        };

        // Make ALL properties of credentials selective
        var selectiveClaims = new[] { "credentials.username", "credentials.password_hash" };

        // Act
        var sdJwt = _issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            _signingKey,
            HashAlgorithm.Sha256);

        // Assert
        var jwtParts = sdJwt.Jwt.Split('.');
        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        var credentialsObj = payload.GetProperty("credentials");

        // Credentials object should ONLY have _sd array (no other properties)
        var propertyCount = 0;
        foreach (var prop in credentialsObj.EnumerateObject())
        {
            propertyCount++;
            Assert.Equal("_sd", prop.Name);
        }
        Assert.Equal(1, propertyCount);

        // _sd array should have 2 digests
        var sdArray = credentialsObj.GetProperty("_sd");
        Assert.Equal(2, sdArray.GetArrayLength());
    }

    [Fact]
    public void EndToEnd_NestedInComplexStructure_WorksCorrectly()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-complex",
            ["profile"] = new Dictionary<string, object>
            {
                { "name", "Alice" },
                { "age", 30 },
                { "contact", new Dictionary<string, object>
                {
                    { "email", "alice@example.com" },
                    { "phone", "+1234567890" }
                }}
            }
        };

        // Note: Currently only supports single-level nesting
        // profile.name is supported, but profile.contact.email would require deeper nesting support
        var selectiveClaims = new[] { "profile.age" };

        // Act
        var sdJwt = _issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            _signingKey,
            HashAlgorithm.Sha256);

        // Assert
        var jwtParts = sdJwt.Jwt.Split('.');
        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        var profileObj = payload.GetProperty("profile");

        // Name and contact should be visible
        Assert.Equal("Alice", profileObj.GetProperty("name").GetString());
        Assert.True(profileObj.TryGetProperty("contact", out _));

        // Age should be in _sd array
        Assert.True(profileObj.TryGetProperty("_sd", out var sdArray));
        Assert.Single(sdArray.EnumerateArray());
        Assert.False(profileObj.TryGetProperty("age", out _));
    }
}
