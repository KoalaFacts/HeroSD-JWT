using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Presentation;
using System.Text.Json;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Presentation;

/// <summary>
/// Tests for DisclosureParser - parses SD-JWT disclosure documents.
/// Validates both 2-element (array element) and 3-element (object property) disclosure formats.
/// </summary>
public class DisclosureParserTests
{
    private readonly DisclosureParser _parser;

    public DisclosureParserTests()
    {
        _parser = new DisclosureParser();
    }

    #region Parse - Valid Cases

    [Fact]
    public void Parse_With3ElementObjectPropertyDisclosure_ReturnsCorrectDisclosure()
    {
        // Arrange - Object property: [salt, claim_name, claim_value]
        var json = "[\"salt123\",\"email\",\"user@example.com\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal("salt123", disclosure.Salt);
        Assert.Equal("email", disclosure.ClaimName);
        Assert.Equal("user@example.com", disclosure.ClaimValue.GetString());
    }

    [Fact]
    public void Parse_With2ElementArrayDisclosure_ReturnsCorrectDisclosure()
    {
        // Arrange - Array element: [salt, claim_value]
        var json = "[\"salt456\",\"value\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal("salt456", disclosure.Salt);
        Assert.Null(disclosure.ClaimName); // Array elements have no claim name
        Assert.Equal("value", disclosure.ClaimValue.GetString());
    }

    [Fact]
    public void Parse_WithStringClaimValue_ParsesCorrectly()
    {
        // Arrange
        var json = "[\"salt\",\"name\",\"John Doe\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal("John Doe", disclosure.ClaimValue.GetString());
    }

    [Fact]
    public void Parse_WithNumberClaimValue_ParsesCorrectly()
    {
        // Arrange
        var json = "[\"salt\",\"age\",42]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal(42, disclosure.ClaimValue.GetInt32());
    }

    [Fact]
    public void Parse_WithObjectClaimValue_ParsesCorrectly()
    {
        // Arrange
        var json = "[\"salt\",\"address\",{\"street\":\"123 Main St\",\"city\":\"Anytown\"}]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal(JsonValueKind.Object, disclosure.ClaimValue.ValueKind);
        Assert.Equal("123 Main St", disclosure.ClaimValue.GetProperty("street").GetString());
        Assert.Equal("Anytown", disclosure.ClaimValue.GetProperty("city").GetString());
    }

    [Fact]
    public void Parse_WithArrayClaimValue_ParsesCorrectly()
    {
        // Arrange
        var json = "[\"salt\",\"roles\",[\"admin\",\"user\"]]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal(JsonValueKind.Array, disclosure.ClaimValue.ValueKind);
        Assert.Equal(2, disclosure.ClaimValue.GetArrayLength());
        Assert.Equal("admin", disclosure.ClaimValue[0].GetString());
        Assert.Equal("user", disclosure.ClaimValue[1].GetString());
    }

    [Fact]
    public void Parse_WithBooleanClaimValue_ParsesCorrectly()
    {
        // Arrange
        var json = "[\"salt\",\"verified\",true]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.True(disclosure.ClaimValue.GetBoolean());
    }

    [Fact]
    public void Parse_WithNullClaimValue_ParsesCorrectly()
    {
        // Arrange
        var json = "[\"salt\",\"optional\",null]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal(JsonValueKind.Null, disclosure.ClaimValue.ValueKind);
    }

    [Fact]
    public void Parse_WithComplexSalt_ParsesCorrectly()
    {
        // Arrange - Salt with special characters
        var json = "[\"abc-123_XYZ!@#\",\"claim\",\"value\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal("abc-123_XYZ!@#", disclosure.Salt);
    }

    [Fact]
    public void Parse_WithEmptyStringClaimValue_ParsesCorrectly()
    {
        // Arrange
        var json = "[\"salt\",\"empty\",\"\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal(string.Empty, disclosure.ClaimValue.GetString());
    }

    #endregion

    #region Parse - Error Cases

    [Fact]
    public void Parse_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _parser.Parse(null!));
    }

    [Fact]
    public void Parse_WithInvalidBase64_ThrowsException()
    {
        // Arrange - Invalid base64url characters
        var invalidBase64 = "!!!not-valid-base64!!!";

        // Act & Assert
        Assert.ThrowsAny<Exception>(() => _parser.Parse(invalidBase64));
    }

    [Fact]
    public void Parse_WithNotJsonArray_ThrowsMalformedDisclosureException()
    {
        // Arrange - Valid JSON but not an array
        var json = "{\"not\":\"an array\"}";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act & Assert
        var exception = Assert.Throws<MalformedDisclosureException>(() => _parser.Parse(base64Url));
        Assert.Contains("Disclosure must be a JSON array", exception.Message);
    }

    [Fact]
    public void Parse_WithEmptyArray_ThrowsMalformedDisclosureException()
    {
        // Arrange - 0-element array
        var json = "[]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act & Assert
        var exception = Assert.Throws<MalformedDisclosureException>(() => _parser.Parse(base64Url));
        Assert.Contains("Disclosure must be a JSON array with 2 elements", exception.Message);
    }

    [Fact]
    public void Parse_With1ElementArray_ThrowsMalformedDisclosureException()
    {
        // Arrange
        var json = "[\"salt\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act & Assert
        var exception = Assert.Throws<MalformedDisclosureException>(() => _parser.Parse(base64Url));
        Assert.Contains("Disclosure must be a JSON array with 2 elements", exception.Message);
    }

    [Fact]
    public void Parse_With4ElementArray_ThrowsMalformedDisclosureException()
    {
        // Arrange
        var json = "[\"salt\",\"name\",\"value\",\"extra\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act & Assert
        var exception = Assert.Throws<MalformedDisclosureException>(() => _parser.Parse(base64Url));
        Assert.Contains("Disclosure must be a JSON array with 2 elements", exception.Message);
    }

    [Fact]
    public void Parse_With5ElementArray_ThrowsMalformedDisclosureException()
    {
        // Arrange
        var json = "[\"salt\",\"name\",\"value\",\"extra1\",\"extra2\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act & Assert
        var exception = Assert.Throws<MalformedDisclosureException>(() => _parser.Parse(base64Url));
        Assert.Contains("Disclosure must be a JSON array with 2 elements", exception.Message);
    }

    [Fact]
    public void Parse_WithNullSalt_ThrowsMalformedDisclosureException()
    {
        // Arrange - Salt is null
        var json = "[null,\"name\",\"value\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act & Assert
        var exception = Assert.Throws<MalformedDisclosureException>(() => _parser.Parse(base64Url));
        Assert.Contains("Disclosure salt cannot be null", exception.Message);
    }

    [Fact]
    public void Parse_With3ElementArrayAndNullClaimName_ThrowsMalformedDisclosureException()
    {
        // Arrange - Claim name is null in 3-element format
        var json = "[\"salt\",null,\"value\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act & Assert
        var exception = Assert.Throws<MalformedDisclosureException>(() => _parser.Parse(base64Url));
        Assert.Contains("Disclosure claim name cannot be null", exception.Message);
    }

    [Fact]
    public void Parse_WithInvalidJson_ThrowsJsonException()
    {
        // Arrange - Malformed JSON
        var json = "[\"salt\",\"name\" invalid json";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act & Assert
        Assert.ThrowsAny<JsonException>(() => _parser.Parse(base64Url));
    }

    #endregion

    #region GetClaimName Tests

    [Fact]
    public void GetClaimName_With3ElementDisclosure_ReturnsClaimName()
    {
        // Arrange
        var json = "[\"salt\",\"email\",\"user@example.com\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var claimName = _parser.GetClaimName(base64Url);

        // Assert
        Assert.Equal("email", claimName);
    }

    [Fact]
    public void GetClaimName_With2ElementDisclosure_ReturnsNull()
    {
        // Arrange - Array element has no claim name
        var json = "[\"salt\",\"value\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var claimName = _parser.GetClaimName(base64Url);

        // Assert
        Assert.Null(claimName);
    }

    [Fact]
    public void GetClaimName_WithMultipleDisclosures_ReturnsCorrectNames()
    {
        // Arrange
        var disclosure1 = Base64UrlEncoder.Encode("[\"salt1\",\"name\",\"John\"]");
        var disclosure2 = Base64UrlEncoder.Encode("[\"salt2\",\"age\",30]");
        var disclosure3 = Base64UrlEncoder.Encode("[\"salt3\",\"verified\",true]");

        // Act & Assert
        Assert.Equal("name", _parser.GetClaimName(disclosure1));
        Assert.Equal("age", _parser.GetClaimName(disclosure2));
        Assert.Equal("verified", _parser.GetClaimName(disclosure3));
    }

    #endregion

    #region Integration Tests

    [Fact]
    public void Parse_RealWorldDisclosure_ParsesCorrectly()
    {
        // Arrange - Real SD-JWT disclosure format
        var json = "[\"6qMQvRL5haj\",\"given_name\",\"太郎\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal("6qMQvRL5haj", disclosure.Salt);
        Assert.Equal("given_name", disclosure.ClaimName);
        Assert.Equal("太郎", disclosure.ClaimValue.GetString());
    }

    [Fact]
    public void Parse_WithUnicodeCharacters_ParsesCorrectly()
    {
        // Arrange
        var json = "[\"salt\",\"name\",\"Zoë 日本語 émoji🎉\"]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        Assert.Equal("Zoë 日本語 émoji🎉", disclosure.ClaimValue.GetString());
    }

    [Fact]
    public void Parse_WithNestedObject_ParsesCorrectly()
    {
        // Arrange
        var json = "[\"salt\",\"address\",{\"street\":\"Main St\",\"geo\":{\"lat\":40.7128,\"lon\":-74.0060}}]";
        var base64Url = Base64UrlEncoder.Encode(json);

        // Act
        var disclosure = _parser.Parse(base64Url);

        // Assert
        var address = disclosure.ClaimValue;
        Assert.Equal(40.7128, address.GetProperty("geo").GetProperty("lat").GetDouble());
        Assert.Equal(-74.0060, address.GetProperty("geo").GetProperty("lon").GetDouble());
    }

    #endregion
}
