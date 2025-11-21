using HeroSdJwt.Models;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.Models;

/// <summary>
/// Tests for the Disclosure model.
/// Validates both 3-element (object property) and 2-element (array element) formats.
/// </summary>
public class DisclosureTests
{
    #region Constructor Tests - Object Property (3-element)

    [Fact]
    public void Constructor_ThreeElement_WithValidParameters_CreatesDisclosure()
    {
        // Arrange
        var salt = "test-salt-123";
        var claimName = "email";
        var claimValue = JsonDocument.Parse("\"test@example.com\"").RootElement;

        // Act
        var disclosure = new Disclosure(salt, claimName, claimValue);

        // Assert
        Assert.Equal(salt, disclosure.Salt);
        Assert.Equal(claimName, disclosure.ClaimName);
        Assert.Equal("test@example.com", disclosure.ClaimValue.GetString());
        Assert.False(disclosure.IsArrayElement);
    }

    [Fact]
    public void Constructor_ThreeElement_WithNullSalt_ThrowsArgumentNullException()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() => new Disclosure(null!, "claimName", claimValue));
    }

    [Fact]
    public void Constructor_ThreeElement_WithNullClaimName_ThrowsArgumentNullException()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() => new Disclosure("salt", null!, claimValue));
    }

    [Fact]
    public void Constructor_ThreeElement_WithEmptySalt_ThrowsArgumentException()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => new Disclosure(string.Empty, "claimName", claimValue));
        Assert.Contains("Salt cannot be empty", exception.Message);
    }

    [Fact]
    public void Constructor_ThreeElement_WithWhitespaceSalt_ThrowsArgumentException()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => new Disclosure("   ", "claimName", claimValue));
        Assert.Contains("Salt cannot be empty", exception.Message);
    }

    [Fact]
    public void Constructor_ThreeElement_WithEmptyClaimName_ThrowsArgumentException()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => new Disclosure("salt", string.Empty, claimValue));
        Assert.Contains("Claim name cannot be empty", exception.Message);
    }

    [Fact]
    public void Constructor_ThreeElement_WithWhitespaceClaimName_ThrowsArgumentException()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => new Disclosure("salt", "   ", claimValue));
        Assert.Contains("Claim name cannot be empty", exception.Message);
    }

    #endregion

    #region Constructor Tests - Array Element (2-element)

    [Fact]
    public void Constructor_TwoElement_WithValidParameters_CreatesArrayElementDisclosure()
    {
        // Arrange
        var salt = "test-salt-456";
        var claimValue = JsonDocument.Parse("42").RootElement;

        // Act
        var disclosure = new Disclosure(salt, claimValue);

        // Assert
        Assert.Equal(salt, disclosure.Salt);
        Assert.Null(disclosure.ClaimName);
        Assert.Equal(42, disclosure.ClaimValue.GetInt32());
        Assert.True(disclosure.IsArrayElement);
    }

    [Fact]
    public void Constructor_TwoElement_WithNullSalt_ThrowsArgumentNullException()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() => new Disclosure(null!, claimValue));
    }

    [Fact]
    public void Constructor_TwoElement_WithEmptySalt_ThrowsArgumentException()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => new Disclosure(string.Empty, claimValue));
        Assert.Contains("Salt cannot be empty", exception.Message);
    }

    [Fact]
    public void Constructor_TwoElement_WithWhitespaceSalt_ThrowsArgumentException()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => new Disclosure("   ", claimValue));
        Assert.Contains("Salt cannot be empty", exception.Message);
    }

    #endregion

    #region IsArrayElement Property Tests

    [Fact]
    public void IsArrayElement_WithThreeElementConstructor_ReturnsFalse()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure = new Disclosure("salt", "claimName", claimValue);

        // Act
        var result = disclosure.IsArrayElement;

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsArrayElement_WithTwoElementConstructor_ReturnsTrue()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure = new Disclosure("salt", claimValue);

        // Act
        var result = disclosure.IsArrayElement;

        // Assert
        Assert.True(result);
    }

    #endregion

    #region ToJson Tests

    [Fact]
    public void ToJson_ObjectProperty_ReturnsThreeElementArray()
    {
        // Arrange
        var salt = "test-salt";
        var claimName = "email";
        var claimValue = JsonDocument.Parse("\"user@example.com\"").RootElement;
        var disclosure = new Disclosure(salt, claimName, claimValue);

        // Act
        var json = disclosure.ToJson();

        // Assert
        var parsed = JsonDocument.Parse(json).RootElement;
        Assert.Equal(JsonValueKind.Array, parsed.ValueKind);
        Assert.Equal(3, parsed.GetArrayLength());
        Assert.Equal(salt, parsed[0].GetString());
        Assert.Equal(claimName, parsed[1].GetString());
        Assert.Equal("user@example.com", parsed[2].GetString());
    }

    [Fact]
    public void ToJson_ArrayElement_ReturnsTwoElementArray()
    {
        // Arrange
        var salt = "array-salt";
        var claimValue = JsonDocument.Parse("123").RootElement;
        var disclosure = new Disclosure(salt, claimValue);

        // Act
        var json = disclosure.ToJson();

        // Assert
        var parsed = JsonDocument.Parse(json).RootElement;
        Assert.Equal(JsonValueKind.Array, parsed.ValueKind);
        Assert.Equal(2, parsed.GetArrayLength());
        Assert.Equal(salt, parsed[0].GetString());
        Assert.Equal(123, parsed[1].GetInt32());
    }

    [Fact]
    public void ToJson_WithComplexJsonValue_SerializesCorrectly()
    {
        // Arrange
        var salt = "complex-salt";
        var complexJson = "{\"name\":\"Alice\",\"age\":30,\"active\":true}";
        var claimValue = JsonDocument.Parse(complexJson).RootElement;
        var disclosure = new Disclosure(salt, "user", claimValue);

        // Act
        var json = disclosure.ToJson();

        // Assert
        var parsed = JsonDocument.Parse(json).RootElement;
        Assert.Equal(3, parsed.GetArrayLength());
        Assert.Equal("user", parsed[1].GetString());

        var valueElement = parsed[2];
        Assert.Equal(JsonValueKind.Object, valueElement.ValueKind);
        Assert.Equal("Alice", valueElement.GetProperty("name").GetString());
        Assert.Equal(30, valueElement.GetProperty("age").GetInt32());
        Assert.True(valueElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public void ToJson_WithArrayValue_SerializesCorrectly()
    {
        // Arrange
        var salt = "array-salt";
        var arrayJson = "[1,2,3,4,5]";
        var claimValue = JsonDocument.Parse(arrayJson).RootElement;
        var disclosure = new Disclosure(salt, "numbers", claimValue);

        // Act
        var json = disclosure.ToJson();

        // Assert
        var parsed = JsonDocument.Parse(json).RootElement;
        Assert.Equal(3, parsed.GetArrayLength());

        var arrayElement = parsed[2];
        Assert.Equal(JsonValueKind.Array, arrayElement.ValueKind);
        Assert.Equal(5, arrayElement.GetArrayLength());
    }

    [Fact]
    public void ToJson_WithBooleanValue_SerializesCorrectly()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("true").RootElement;
        var disclosure = new Disclosure("salt", "active", claimValue);

        // Act
        var json = disclosure.ToJson();

        // Assert
        var parsed = JsonDocument.Parse(json).RootElement;
        Assert.True(parsed[2].GetBoolean());
    }

    [Fact]
    public void ToJson_WithNullValue_SerializesCorrectly()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("null").RootElement;
        var disclosure = new Disclosure("salt", "optional", claimValue);

        // Act
        var json = disclosure.ToJson();

        // Assert
        var parsed = JsonDocument.Parse(json).RootElement;
        Assert.Equal(JsonValueKind.Null, parsed[2].ValueKind);
    }

    #endregion

    #region Equals Tests

    [Fact]
    public void Equals_WithSameValues_ReturnsTrue()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure1 = new Disclosure("salt", "claim", claimValue);
        var disclosure2 = new Disclosure("salt", "claim", claimValue);

        // Act
        var result = disclosure1.Equals(disclosure2);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Equals_WithDifferentSalt_ReturnsFalse()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure1 = new Disclosure("salt1", "claim", claimValue);
        var disclosure2 = new Disclosure("salt2", "claim", claimValue);

        // Act
        var result = disclosure1.Equals(disclosure2);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Equals_WithDifferentClaimName_ReturnsFalse()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure1 = new Disclosure("salt", "claim1", claimValue);
        var disclosure2 = new Disclosure("salt", "claim2", claimValue);

        // Act
        var result = disclosure1.Equals(disclosure2);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Equals_WithDifferentClaimValue_ReturnsFalse()
    {
        // Arrange
        var value1 = JsonDocument.Parse("\"value1\"").RootElement;
        var value2 = JsonDocument.Parse("\"value2\"").RootElement;
        var disclosure1 = new Disclosure("salt", "claim", value1);
        var disclosure2 = new Disclosure("salt", "claim", value2);

        // Act
        var result = disclosure1.Equals(disclosure2);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Equals_ArrayElementWithSameValues_ReturnsTrue()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("42").RootElement;
        var disclosure1 = new Disclosure("salt", claimValue);
        var disclosure2 = new Disclosure("salt", claimValue);

        // Act
        var result = disclosure1.Equals(disclosure2);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void EqualsObject_WithNonDisclosureObject_ReturnsFalse()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure = new Disclosure("salt", "claim", claimValue);
        var notADisclosure = "not a disclosure";

        // Act
        var result = disclosure.Equals(notADisclosure);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void EqualsObject_WithNull_ReturnsFalse()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure = new Disclosure("salt", "claim", claimValue);

        // Act
        var result = disclosure.Equals(null);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void EqualsObject_WithSameDisclosureAsObject_ReturnsTrue()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure1 = new Disclosure("salt", "claim", claimValue);
        object disclosure2 = new Disclosure("salt", "claim", claimValue);

        // Act
        var result = disclosure1.Equals(disclosure2);

        // Assert
        Assert.True(result);
    }

    #endregion

    #region GetHashCode Tests

    [Fact]
    public void GetHashCode_WithSameValues_ReturnsSameHashCode()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure1 = new Disclosure("salt", "claim", claimValue);
        var disclosure2 = new Disclosure("salt", "claim", claimValue);

        // Act
        var hash1 = disclosure1.GetHashCode();
        var hash2 = disclosure2.GetHashCode();

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void GetHashCode_WithDifferentValues_ReturnsDifferentHashCodes()
    {
        // Arrange
        var value1 = JsonDocument.Parse("\"value1\"").RootElement;
        var value2 = JsonDocument.Parse("\"value2\"").RootElement;
        var disclosure1 = new Disclosure("salt", "claim", value1);
        var disclosure2 = new Disclosure("salt", "claim", value2);

        // Act
        var hash1 = disclosure1.GetHashCode();
        var hash2 = disclosure2.GetHashCode();

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    #endregion

    #region Operator Tests

    [Fact]
    public void OperatorEquals_WithEqualDisclosures_ReturnsTrue()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure1 = new Disclosure("salt", "claim", claimValue);
        var disclosure2 = new Disclosure("salt", "claim", claimValue);

        // Act
        var result = disclosure1 == disclosure2;

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void OperatorEquals_WithDifferentDisclosures_ReturnsFalse()
    {
        // Arrange
        var value1 = JsonDocument.Parse("\"value1\"").RootElement;
        var value2 = JsonDocument.Parse("\"value2\"").RootElement;
        var disclosure1 = new Disclosure("salt", "claim", value1);
        var disclosure2 = new Disclosure("salt", "claim", value2);

        // Act
        var result = disclosure1 == disclosure2;

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void OperatorNotEquals_WithEqualDisclosures_ReturnsFalse()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure1 = new Disclosure("salt", "claim", claimValue);
        var disclosure2 = new Disclosure("salt", "claim", claimValue);

        // Act
        var result = disclosure1 != disclosure2;

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void OperatorNotEquals_WithDifferentDisclosures_ReturnsTrue()
    {
        // Arrange
        var value1 = JsonDocument.Parse("\"value1\"").RootElement;
        var value2 = JsonDocument.Parse("\"value2\"").RootElement;
        var disclosure1 = new Disclosure("salt", "claim", value1);
        var disclosure2 = new Disclosure("salt", "claim", value2);

        // Act
        var result = disclosure1 != disclosure2;

        // Assert
        Assert.True(result);
    }

    #endregion

    #region ToString Tests

    [Fact]
    public void ToString_ObjectProperty_ReturnsFormattedString()
    {
        // Arrange
        var salt = "verylongsaltvalue123456789";
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure = new Disclosure(salt, "email", claimValue);

        // Act
        var result = disclosure.ToString();

        // Assert
        Assert.Contains("Disclosure", result);
        Assert.Contains("email", result);
        Assert.Contains("ClaimName", result);
        Assert.DoesNotContain("ArrayElement", result);
    }

    [Fact]
    public void ToString_ArrayElement_IndicatesArrayElement()
    {
        // Arrange
        var salt = "arraysalt";
        var claimValue = JsonDocument.Parse("42").RootElement;
        var disclosure = new Disclosure(salt, claimValue);

        // Act
        var result = disclosure.ToString();

        // Assert
        Assert.Contains("Disclosure", result);
        Assert.Contains("ArrayElement", result);
        Assert.DoesNotContain("ClaimName", result);
    }

    [Fact]
    public void ToString_TruncatesSalt()
    {
        // Arrange
        var longSalt = "this_is_a_very_long_salt_value_that_should_be_truncated";
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure = new Disclosure(longSalt, "claim", claimValue);

        // Act
        var result = disclosure.ToString();

        // Assert
        Assert.Contains("...", result);
        Assert.DoesNotContain("truncated", result);
    }

    #endregion

    #region Collection Usage Tests

    [Fact]
    public void Disclosure_CanBeUsedInHashSet()
    {
        // Arrange
        var value1 = JsonDocument.Parse("\"value1\"").RootElement;
        var value2 = JsonDocument.Parse("\"value2\"").RootElement;
        var disclosure1 = new Disclosure("salt1", "claim", value1);
        var disclosure2 = new Disclosure("salt2", "claim", value2);
        var disclosure1Duplicate = new Disclosure("salt1", "claim", value1);

        var hashSet = new HashSet<Disclosure>();

        // Act
        _ = hashSet.Add(disclosure1);
        _ = hashSet.Add(disclosure2);
        _ = hashSet.Add(disclosure1Duplicate); // Should not be added

        // Assert
        Assert.Equal(2, hashSet.Count);
        Assert.Contains(disclosure1, hashSet);
        Assert.Contains(disclosure2, hashSet);
    }

    [Fact]
    public void Disclosure_CanBeUsedAsDictionaryKey()
    {
        // Arrange
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var disclosure = new Disclosure("salt", "claim", claimValue);
        var dict = new Dictionary<Disclosure, string>
        {
            // Act
            [disclosure] = "test-data"
        };
        var retrievedValue = dict[disclosure];

        // Assert
        Assert.Equal("test-data", retrievedValue);
    }

    #endregion
}
