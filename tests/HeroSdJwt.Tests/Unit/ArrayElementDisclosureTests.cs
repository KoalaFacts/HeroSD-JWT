using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using System.Text.Json;
using Xunit;
using Base64UrlEncoder = HeroSdJwt.Encoding.Base64UrlEncoder;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for array element selective disclosure (2-element format).
/// Per SD-JWT spec section 4.2.4, array elements use [salt, value] format.
/// </summary>
public class ArrayElementDisclosureTests
{
    [Fact]
    public void DisclosureGenerator_GenerateArrayElementDisclosure_Creates2ElementFormat()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var value = JsonDocument.Parse("\"PhD\"").RootElement;

        // Act
        var disclosure = generator.GenerateArrayElementDisclosure(value);

        // Assert
        Assert.NotNull(disclosure);
        Assert.NotEmpty(disclosure);

        // Decode and verify it's a 2-element array
        var decodedJson = Base64UrlEncoder.DecodeString(disclosure);
        var array = JsonDocument.Parse(decodedJson).RootElement;

        Assert.Equal(JsonValueKind.Array, array.ValueKind);
        Assert.Equal(2, array.GetArrayLength());

        // Verify structure: [salt, value]
        Assert.Equal(JsonValueKind.String, array[0].ValueKind); // salt
        Assert.Equal("PhD", array[1].GetString()); // value
    }

    [Fact]
    public void DisclosureParser_Parse2ElementArray_ReturnsArrayElementDisclosure()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var value = JsonDocument.Parse("42").RootElement;
        var disclosure = generator.GenerateArrayElementDisclosure(value);

        // Act
        var parsed = DisclosureParser.Parse(disclosure);

        // Assert
        Assert.True(parsed.IsArrayElement);
        Assert.Null(parsed.ClaimName);
        Assert.Equal(42, parsed.ClaimValue.GetInt32());
        Assert.NotEmpty(parsed.Salt);
    }

    [Fact]
    public void DisclosureParser_Parse3ElementArray_ReturnsObjectPropertyDisclosure()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var value = JsonDocument.Parse("\"test@example.com\"").RootElement;
        var disclosure = generator.GenerateDisclosure("email", value);

        // Act
        var parsed = DisclosureParser.Parse(disclosure);

        // Assert
        Assert.False(parsed.IsArrayElement);
        Assert.Equal("email", parsed.ClaimName);
        Assert.Equal("test@example.com", parsed.ClaimValue.GetString());
        Assert.NotEmpty(parsed.Salt);
    }

    [Fact]
    public void DisclosureParser_ParseInvalidArrayLength_ThrowsException()
    {
        // Arrange - Create a 4-element array (invalid)
        var invalidArray = new object[] { "salt", "name", "value", "extra" };
        var json = JsonSerializer.Serialize(invalidArray);
        var encoded = Base64UrlEncoder.Encode(json);

        // Act & Assert
        var exception = Assert.Throws<MalformedDisclosureException>(() =>
            DisclosureParser.Parse(encoded));

        Assert.Contains("2 elements", exception.Message);
        Assert.Contains("3 elements", exception.Message);
    }

    [Fact]
    public void DisclosureParser_GetClaimName_ReturnsNullForArrayElements()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var value = JsonDocument.Parse("\"MS\"").RootElement;
        var disclosure = generator.GenerateArrayElementDisclosure(value);

        // Act
        var claimName = DisclosureParser.GetClaimName(disclosure);

        // Assert
        Assert.Null(claimName);
    }

    [Fact]
    public void Disclosure_ToJson_ArrayElement_Produces2ElementArray()
    {
        // Arrange
        var value = JsonDocument.Parse("\"BS\"").RootElement;
        var disclosure = new Disclosure("test-salt", value);

        // Act
        var json = disclosure.ToJson();

        // Assert
        var array = JsonDocument.Parse(json).RootElement;
        Assert.Equal(JsonValueKind.Array, array.ValueKind);
        Assert.Equal(2, array.GetArrayLength());
        Assert.Equal("test-salt", array[0].GetString());
        Assert.Equal("BS", array[1].GetString());
    }

    [Fact]
    public void Disclosure_ToJson_ObjectProperty_Produces3ElementArray()
    {
        // Arrange
        var value = JsonDocument.Parse("\"test@example.com\"").RootElement;
        var disclosure = new Disclosure("test-salt", "email", value);

        // Act
        var json = disclosure.ToJson();

        // Assert
        var array = JsonDocument.Parse(json).RootElement;
        Assert.Equal(JsonValueKind.Array, array.ValueKind);
        Assert.Equal(3, array.GetArrayLength());
        Assert.Equal("test-salt", array[0].GetString());
        Assert.Equal("email", array[1].GetString());
        Assert.Equal("test@example.com", array[2].GetString());
    }

    [Fact]
    public void Disclosure_ToString_ArrayElement_ShowsArrayElementLabel()
    {
        // Arrange
        var value = JsonDocument.Parse("123").RootElement;
        var disclosure = new Disclosure("test-salt-value", value);

        // Act
        var result = disclosure.ToString();

        // Assert
        Assert.Contains("ArrayElement", result);
        Assert.Contains("test-sal", result); // Truncated salt
    }

    [Fact]
    public void Disclosure_ToString_ObjectProperty_ShowsClaimName()
    {
        // Arrange
        var value = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure = new Disclosure("test-salt-value", "testClaim", value);

        // Act
        var result = disclosure.ToString();

        // Assert
        Assert.Contains("testClaim", result);
        Assert.Contains("test-sal", result); // Truncated salt
    }

    [Fact]
    public void ArrayElementDisclosure_ComplexValue_WorksCorrectly()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var complexValue = JsonDocument.Parse("""
            {
                "institution": "MIT",
                "year": 2015,
                "degree": "PhD"
            }
            """).RootElement;

        // Act
        var disclosure = generator.GenerateArrayElementDisclosure(complexValue);
        var parsed = DisclosureParser.Parse(disclosure);

        // Assert
        Assert.True(parsed.IsArrayElement);
        Assert.Null(parsed.ClaimName);
        Assert.Equal(JsonValueKind.Object, parsed.ClaimValue.ValueKind);
        Assert.Equal("MIT", parsed.ClaimValue.GetProperty("institution").GetString());
        Assert.Equal(2015, parsed.ClaimValue.GetProperty("year").GetInt32());
        Assert.Equal("PhD", parsed.ClaimValue.GetProperty("degree").GetString());
    }
}
