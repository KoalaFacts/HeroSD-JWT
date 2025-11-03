using HeroSdJwt.Models;
using Xunit;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for ClaimPath parsing to support array element syntax.
/// </summary>
public class ClaimPathTests
{
    [Fact]
    public void Parse_SimpleClaimName_ReturnsNonArrayPath()
    {
        // Act
        var path = ClaimPath.Parse("email");

        // Assert
        Assert.Equal("email", path.BaseName);
        Assert.Null(path.ArrayIndex);
        Assert.False(path.IsArrayElement);
        Assert.Equal("email", path.OriginalSpec);
    }

    [Fact]
    public void Parse_ArrayElement_ReturnsArrayPath()
    {
        // Act
        var path = ClaimPath.Parse("degrees[1]");

        // Assert
        Assert.Equal("degrees", path.BaseName);
        Assert.Equal(1, path.ArrayIndex);
        Assert.True(path.IsArrayElement);
        Assert.Equal("degrees[1]", path.OriginalSpec);
    }

    [Fact]
    public void Parse_ArrayElementZeroIndex_ReturnsArrayPath()
    {
        // Act
        var path = ClaimPath.Parse("items[0]");

        // Assert
        Assert.Equal("items", path.BaseName);
        Assert.Equal(0, path.ArrayIndex);
        Assert.True(path.IsArrayElement);
    }

    [Fact]
    public void Parse_ArrayElementLargeIndex_ReturnsArrayPath()
    {
        // Act
        var path = ClaimPath.Parse("data[999]");

        // Assert
        Assert.Equal("data", path.BaseName);
        Assert.Equal(999, path.ArrayIndex);
        Assert.True(path.IsArrayElement);
    }

    [Fact]
    public void Parse_EmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse(""));
        Assert.Contains("empty or whitespace", exception.Message);
    }

    [Fact]
    public void Parse_WhitespaceString_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse("   "));
        Assert.Contains("empty or whitespace", exception.Message);
    }

    [Fact]
    public void Parse_MissingClosingBracket_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse("degrees[1"));
        Assert.Contains("missing closing ']'", exception.Message);
    }

    [Fact]
    public void Parse_EmptyIndex_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse("degrees[]"));
        Assert.Contains("array index cannot be empty", exception.Message);
    }

    [Fact]
    public void Parse_NonNumericIndex_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse("degrees[abc]"));
        Assert.Contains("must be a valid integer", exception.Message);
    }

    [Fact]
    public void Parse_NegativeIndex_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse("degrees[-1]"));
        Assert.Contains("cannot be negative", exception.Message);
    }

    [Fact]
    public void Parse_BracketAtStart_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse("[1]"));
        Assert.Contains("must have a claim name before '['", exception.Message);
    }

    [Fact]
    public void Parse_NestedProperty_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse("education[0].institution"));
        Assert.Contains("nested properties in arrays are not yet supported", exception.Message);
    }

    [Fact]
    public void ToString_ReturnsOriginalSpec()
    {
        // Arrange
        var path = ClaimPath.Parse("degrees[2]");

        // Act
        var result = path.ToString();

        // Assert
        Assert.Equal("degrees[2]", result);
    }

    // Nested property tests
    [Fact]
    public void Parse_NestedProperty_ReturnsNestedPath()
    {
        // Act
        var path = ClaimPath.Parse("address.street");

        // Assert
        Assert.Equal("address", path.BaseName);
        Assert.Equal("street", path.NestedPath);
        Assert.True(path.IsNested);
        Assert.False(path.IsArrayElement);
        Assert.Equal(new[] { "address", "street" }, path.PathComponents);
    }

    [Fact]
    public void Parse_DeeplyNestedProperty_ReturnsCorrectPath()
    {
        // Act
        var path = ClaimPath.Parse("address.geo.coordinates");

        // Assert
        Assert.Equal("address", path.BaseName);
        Assert.Equal("geo.coordinates", path.NestedPath);
        Assert.True(path.IsNested);
        Assert.Equal(new[] { "address", "geo", "coordinates" }, path.PathComponents);
    }

    [Fact]
    public void Parse_PathStartingWithDot_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse(".address"));
        Assert.Contains("cannot start with '.'", exception.Message);
    }

    [Fact]
    public void Parse_PathEndingWithDot_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse("address."));
        Assert.Contains("cannot end with '.'", exception.Message);
    }

    [Fact]
    public void Parse_PathWithEmptyComponent_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ClaimPath.Parse("address..street"));
        // Security fix: ".." is now caught by path traversal validation
        Assert.Contains("path traversal", exception.Message);
    }
}
