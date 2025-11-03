using HeroSdJwt.Issuance;
using System.Text;
using System.Text.Json;
using Xunit;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Unit tests for DisclosureGenerator.
/// Tests the generation of disclosures with cryptographically secure salts.
/// Written BEFORE implementation (TDD).
/// </summary>
public class DisclosureGeneratorTests
{
    [Fact]
    public void GenerateDisclosure_WithValidInputs_ReturnsBase64UrlEncodedString()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "email";
        var claimValue = JsonDocument.Parse("\"user@example.com\"").RootElement;

        // Act
        var disclosure = generator.GenerateDisclosure(claimName, claimValue);

        // Assert
        Assert.NotNull(disclosure);
        Assert.NotEmpty(disclosure);
        // Base64url should not contain +, /, or =
        Assert.DoesNotContain("+", disclosure);
        Assert.DoesNotContain("/", disclosure);
        Assert.DoesNotContain("=", disclosure);
    }

    [Fact]
    public void GenerateDisclosure_SaltIsAtLeast128Bits()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "age";
        var claimValue = JsonDocument.Parse("30").RootElement;

        // Act
        var disclosure = generator.GenerateDisclosure(claimName, claimValue);

        // Assert
        // Decode the disclosure to get the salt
        var decodedDisclosure = DecodeDisclosure(disclosure);

        // Disclosure is an array: [salt, claim_name, claim_value]
        var saltString = decodedDisclosure[0].GetString()!;
        var saltBytes = Convert.FromBase64String(ConvertFromBase64Url(saltString));

        // Salt must be at least 128 bits (16 bytes)
        Assert.True(saltBytes.Length >= 16, $"Salt length is {saltBytes.Length} bytes, expected >= 16 bytes");
    }

    [Fact]
    public void GenerateDisclosure_ReturnsJsonArrayFormat()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "country";
        var claimValue = JsonDocument.Parse("\"US\"").RootElement;

        // Act
        var disclosure = generator.GenerateDisclosure(claimName, claimValue);

        // Assert
        var decoded = DecodeDisclosure(disclosure);

        // Should be JSON array with 3 elements: [salt, claim_name, claim_value]
        Assert.Equal(JsonValueKind.Array, decoded.ValueKind);
        Assert.Equal(3, decoded.GetArrayLength());

        // Verify structure
        var salt = decoded[0].GetString();
        var name = decoded[1].GetString();
        var value = decoded[2].GetString();

        Assert.NotNull(salt);
        Assert.NotEmpty(salt!);
        Assert.Equal(claimName, name);
        Assert.Equal("US", value);
    }

    [Fact]
    public void GenerateDisclosure_WithComplexClaimValue_PreservesStructure()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "address";
        var claimValue = JsonDocument.Parse("{\"street\":\"123 Main St\",\"city\":\"New York\"}").RootElement;

        // Act
        var disclosure = generator.GenerateDisclosure(claimName, claimValue);

        // Assert
        var decoded = DecodeDisclosure(disclosure);
        var value = decoded[2];

        Assert.Equal(JsonValueKind.Object, value.ValueKind);
        Assert.True(value.TryGetProperty("street", out var street));
        Assert.Equal("123 Main St", street.GetString());
        Assert.True(value.TryGetProperty("city", out var city));
        Assert.Equal("New York", city.GetString());
    }

    [Fact]
    public void GenerateDisclosure_WithNullClaimName_ThrowsArgumentNullException()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            generator.GenerateDisclosure(null!, claimValue));
    }

    [Fact]
    public void GenerateDisclosure_WithEmptyClaimName_ThrowsArgumentException()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            generator.GenerateDisclosure(string.Empty, claimValue));
    }

    [Fact]
    public void GenerateDisclosure_MultipleCallsProduceDifferentSalts()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "test";
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act
        var disclosure1 = generator.GenerateDisclosure(claimName, claimValue);
        var disclosure2 = generator.GenerateDisclosure(claimName, claimValue);
        var disclosure3 = generator.GenerateDisclosure(claimName, claimValue);

        // Assert
        // Each disclosure should have a different salt
        var decoded1 = DecodeDisclosure(disclosure1);
        var decoded2 = DecodeDisclosure(disclosure2);
        var decoded3 = DecodeDisclosure(disclosure3);

        var salt1 = decoded1[0].GetString();
        var salt2 = decoded2[0].GetString();
        var salt3 = decoded3[0].GetString();

        Assert.NotEqual(salt1, salt2);
        Assert.NotEqual(salt2, salt3);
        Assert.NotEqual(salt1, salt3);
    }

    // Helper methods
    private static JsonElement DecodeDisclosure(string base64UrlDisclosure)
    {
        var base64 = ConvertFromBase64Url(base64UrlDisclosure);
        var bytes = Convert.FromBase64String(base64);
        var json = System.Text.Encoding.UTF8.GetString(bytes);
        return JsonDocument.Parse(json).RootElement;
    }

    private static string ConvertFromBase64Url(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        var padding = (4 - base64.Length % 4) % 4;
        return base64 + new string('=', padding);
    }
}
