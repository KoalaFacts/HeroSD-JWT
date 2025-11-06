using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using Xunit;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit.Models;

/// <summary>
/// Tests for the SdJwt model.
/// Validates SD-JWT construction, combined format generation, and properties.
/// </summary>
public class SdJwtTests
{
    private const string ValidJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

    #region Constructor Tests

    [Fact]
    public void Constructor_WithValidParameters_CreatesSdJwt()
    {
        // Arrange
        var jwt = ValidJwt;
        var disclosures = new List<string> { "disclosure1", "disclosure2" };
        var hashAlgorithm = HashAlgorithm.Sha256;
        var keyBindingJwt = "kb.jwt.here";

        // Act
        var sdJwt = new SdJwt(jwt, disclosures, hashAlgorithm, keyBindingJwt);

        // Assert
        Assert.Equal(jwt, sdJwt.Jwt);
        Assert.Equal(2, sdJwt.Disclosures.Count);
        Assert.Equal("disclosure1", sdJwt.Disclosures[0]);
        Assert.Equal("disclosure2", sdJwt.Disclosures[1]);
        Assert.Equal(hashAlgorithm, sdJwt.HashAlgorithm);
        Assert.Equal(keyBindingJwt, sdJwt.KeyBindingJwt);
    }

    [Fact]
    public void Constructor_WithoutKeyBinding_CreatesValidSdJwt()
    {
        // Arrange
        var jwt = ValidJwt;
        var disclosures = new List<string> { "disclosure1" };
        var hashAlgorithm = HashAlgorithm.Sha512;

        // Act
        var sdJwt = new SdJwt(jwt, disclosures, hashAlgorithm);

        // Assert
        Assert.Equal(jwt, sdJwt.Jwt);
        Assert.Single(sdJwt.Disclosures);
        Assert.Equal(hashAlgorithm, sdJwt.HashAlgorithm);
        Assert.Null(sdJwt.KeyBindingJwt);
    }

    [Fact]
    public void Constructor_WithEmptyDisclosures_CreatesValidSdJwt()
    {
        // Arrange
        var jwt = ValidJwt;
        var disclosures = new List<string>();
        var hashAlgorithm = HashAlgorithm.Sha256;

        // Act
        var sdJwt = new SdJwt(jwt, disclosures, hashAlgorithm);

        // Assert
        Assert.Equal(jwt, sdJwt.Jwt);
        Assert.Empty(sdJwt.Disclosures);
        Assert.Equal(hashAlgorithm, sdJwt.HashAlgorithm);
    }

    [Fact]
    public void Constructor_WithNullJwt_ThrowsArgumentNullException()
    {
        // Arrange
        var disclosures = new List<string> { "disclosure1" };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new SdJwt(null!, disclosures, HashAlgorithm.Sha256));
    }

    [Fact]
    public void Constructor_WithNullDisclosures_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new SdJwt(ValidJwt, null!, HashAlgorithm.Sha256));
    }

    [Fact]
    public void Constructor_WithEmptyJwt_ThrowsArgumentException()
    {
        // Arrange
        var disclosures = new List<string> { "disclosure1" };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new SdJwt(string.Empty, disclosures, HashAlgorithm.Sha256));
        Assert.Contains("JWT cannot be empty", exception.Message);
    }

    [Fact]
    public void Constructor_WithWhitespaceJwt_ThrowsArgumentException()
    {
        // Arrange
        var disclosures = new List<string> { "disclosure1" };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new SdJwt("   ", disclosures, HashAlgorithm.Sha256));
        Assert.Contains("JWT cannot be empty", exception.Message);
    }

    [Fact]
    public void Constructor_CreatesReadOnlyDisclosuresList()
    {
        // Arrange
        var disclosures = new List<string> { "disclosure1", "disclosure2" };
        var sdJwt = new SdJwt(ValidJwt, disclosures, HashAlgorithm.Sha256);

        // Act & Assert
        Assert.IsAssignableFrom<IReadOnlyList<string>>(sdJwt.Disclosures);

        // Verify it's truly read-only by checking we can't cast to modifiable list
        Assert.False(sdJwt.Disclosures is List<string>);
    }

    [Fact]
    public void Constructor_CopiesDisclosuresCollection()
    {
        // Arrange
        var disclosures = new List<string> { "disclosure1" };
        var sdJwt = new SdJwt(ValidJwt, disclosures, HashAlgorithm.Sha256);

        // Act - Modify original list
        disclosures.Add("disclosure2");

        // Assert - SdJwt's list should not be affected
        Assert.Single(sdJwt.Disclosures);
        Assert.Equal("disclosure1", sdJwt.Disclosures[0]);
    }

    #endregion

    #region ToCombinedFormat Tests

    [Fact]
    public void ToCombinedFormat_WithNoDisclosuresAndNoKeyBinding_ReturnsJwtWithEmptyEnd()
    {
        // Arrange
        var jwt = ValidJwt;
        var sdJwt = new SdJwt(jwt, new List<string>(), HashAlgorithm.Sha256);

        // Act
        var combined = sdJwt.ToCombinedFormat();

        // Assert
        Assert.Equal($"{jwt}~", combined);
    }

    [Fact]
    public void ToCombinedFormat_WithDisclosuresNoKeyBinding_ReturnsCorrectFormat()
    {
        // Arrange
        var jwt = ValidJwt;
        var disclosures = new List<string> { "disc1", "disc2", "disc3" };
        var sdJwt = new SdJwt(jwt, disclosures, HashAlgorithm.Sha256);

        // Act
        var combined = sdJwt.ToCombinedFormat();

        // Assert
        Assert.Equal($"{jwt}~disc1~disc2~disc3~", combined);
    }

    [Fact]
    public void ToCombinedFormat_WithKeyBindingNoDisclosures_ReturnsCorrectFormat()
    {
        // Arrange
        var jwt = ValidJwt;
        var keyBinding = "kb.jwt";
        var sdJwt = new SdJwt(jwt, new List<string>(), HashAlgorithm.Sha256, keyBinding);

        // Act
        var combined = sdJwt.ToCombinedFormat();

        // Assert
        Assert.Equal($"{jwt}~{keyBinding}", combined);
    }

    [Fact]
    public void ToCombinedFormat_WithDisclosuresAndKeyBinding_ReturnsCorrectFormat()
    {
        // Arrange
        var jwt = ValidJwt;
        var disclosures = new List<string> { "disc1", "disc2" };
        var keyBinding = "kb.jwt";
        var sdJwt = new SdJwt(jwt, disclosures, HashAlgorithm.Sha256, keyBinding);

        // Act
        var combined = sdJwt.ToCombinedFormat();

        // Assert
        Assert.Equal($"{jwt}~disc1~disc2~{keyBinding}", combined);
    }

    [Fact]
    public void ToCombinedFormat_WithEmptyStringKeyBinding_TreatsAsNoKeyBinding()
    {
        // Arrange
        var jwt = ValidJwt;
        var disclosures = new List<string> { "disc1" };
        var sdJwt = new SdJwt(jwt, disclosures, HashAlgorithm.Sha256, string.Empty);

        // Act
        var combined = sdJwt.ToCombinedFormat();

        // Assert
        Assert.Equal($"{jwt}~disc1~", combined);
    }

    [Fact]
    public void ToCombinedFormat_WithManyDisclosures_ReturnsCorrectFormat()
    {
        // Arrange
        var jwt = ValidJwt;
        var disclosures = Enumerable.Range(1, 10).Select(i => $"disclosure{i}").ToList();
        var sdJwt = new SdJwt(jwt, disclosures, HashAlgorithm.Sha256);

        // Act
        var combined = sdJwt.ToCombinedFormat();

        // Assert
        var parts = combined.Split('~');
        Assert.Equal(12, parts.Length); // JWT + 10 disclosures + empty KB
        Assert.Equal(jwt, parts[0]);
        Assert.Equal("disclosure1", parts[1]);
        Assert.Equal("disclosure10", parts[10]);
        Assert.Equal(string.Empty, parts[11]);
    }

    #endregion

    #region ToString Tests

    [Fact]
    public void ToString_WithKeyBinding_IndicatesKeyBinding()
    {
        // Arrange
        var disclosures = new List<string> { "disc1", "disc2" };
        var sdJwt = new SdJwt(ValidJwt, disclosures, HashAlgorithm.Sha256, "kb.jwt");

        // Act
        var result = sdJwt.ToString();

        // Assert
        Assert.Contains("SdJwt", result);
        Assert.Contains("Disclosures=2", result);
        Assert.Contains("Sha256", result);
        Assert.Contains("with KB", result);
        Assert.DoesNotContain("no KB", result);
    }

    [Fact]
    public void ToString_WithoutKeyBinding_IndicatesNoKeyBinding()
    {
        // Arrange
        var disclosures = new List<string> { "disc1" };
        var sdJwt = new SdJwt(ValidJwt, disclosures, HashAlgorithm.Sha512);

        // Act
        var result = sdJwt.ToString();

        // Assert
        Assert.Contains("SdJwt", result);
        Assert.Contains("Disclosures=1", result);
        Assert.Contains("Sha512", result);
        Assert.Contains("no KB", result);
        Assert.DoesNotContain("with KB", result);
    }

    [Fact]
    public void ToString_WithNoDisclosures_ShowsZeroDisclosures()
    {
        // Arrange
        var sdJwt = new SdJwt(ValidJwt, new List<string>(), HashAlgorithm.Sha384);

        // Act
        var result = sdJwt.ToString();

        // Assert
        Assert.Contains("Disclosures=0", result);
        Assert.Contains("Sha384", result);
    }

    [Fact]
    public void ToString_WithMultipleDisclosures_ShowsCorrectCount()
    {
        // Arrange
        var disclosures = new List<string> { "d1", "d2", "d3", "d4", "d5" };
        var sdJwt = new SdJwt(ValidJwt, disclosures, HashAlgorithm.Sha256);

        // Act
        var result = sdJwt.ToString();

        // Assert
        Assert.Contains("Disclosures=5", result);
    }

    #endregion

    #region Properties Tests

    [Fact]
    public void Jwt_Property_ReturnsOriginalJwt()
    {
        // Arrange
        var jwt = "my.custom.jwt";
        var sdJwt = new SdJwt(jwt, new List<string>(), HashAlgorithm.Sha256);

        // Act
        var result = sdJwt.Jwt;

        // Assert
        Assert.Equal(jwt, result);
    }

    [Fact]
    public void Disclosures_Property_ReturnsAllDisclosures()
    {
        // Arrange
        var disclosures = new List<string> { "disc1", "disc2", "disc3" };
        var sdJwt = new SdJwt(ValidJwt, disclosures, HashAlgorithm.Sha256);

        // Act
        var result = sdJwt.Disclosures;

        // Assert
        Assert.Equal(3, result.Count);
        Assert.Equal("disc1", result[0]);
        Assert.Equal("disc2", result[1]);
        Assert.Equal("disc3", result[2]);
    }

    [Fact]
    public void HashAlgorithm_Property_ReturnsCorrectAlgorithm()
    {
        // Arrange & Act
        var sha256SdJwt = new SdJwt(ValidJwt, new List<string>(), HashAlgorithm.Sha256);
        var sha384SdJwt = new SdJwt(ValidJwt, new List<string>(), HashAlgorithm.Sha384);
        var sha512SdJwt = new SdJwt(ValidJwt, new List<string>(), HashAlgorithm.Sha512);

        // Assert
        Assert.Equal(HashAlgorithm.Sha256, sha256SdJwt.HashAlgorithm);
        Assert.Equal(HashAlgorithm.Sha384, sha384SdJwt.HashAlgorithm);
        Assert.Equal(HashAlgorithm.Sha512, sha512SdJwt.HashAlgorithm);
    }

    [Fact]
    public void KeyBindingJwt_Property_WithKeyBinding_ReturnsKeyBinding()
    {
        // Arrange
        var keyBinding = "my.kb.jwt";
        var sdJwt = new SdJwt(ValidJwt, new List<string>(), HashAlgorithm.Sha256, keyBinding);

        // Act
        var result = sdJwt.KeyBindingJwt;

        // Assert
        Assert.Equal(keyBinding, result);
    }

    [Fact]
    public void KeyBindingJwt_Property_WithoutKeyBinding_ReturnsNull()
    {
        // Arrange
        var sdJwt = new SdJwt(ValidJwt, new List<string>(), HashAlgorithm.Sha256);

        // Act
        var result = sdJwt.KeyBindingJwt;

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region Edge Case Tests

    [Fact]
    public void SdJwt_WithVeryLongJwt_WorksCorrectly()
    {
        // Arrange
        var longJwt = new string('a', 10000);
        var sdJwt = new SdJwt(longJwt, new List<string>(), HashAlgorithm.Sha256);

        // Act
        var result = sdJwt.Jwt;

        // Assert
        Assert.Equal(10000, result.Length);
        Assert.Equal(longJwt, result);
    }

    [Fact]
    public void SdJwt_WithSpecialCharactersInJwt_WorksCorrectly()
    {
        // Arrange
        var specialJwt = "jwt.with-special_chars+/=";
        var sdJwt = new SdJwt(specialJwt, new List<string>(), HashAlgorithm.Sha256);

        // Act
        var result = sdJwt.Jwt;

        // Assert
        Assert.Equal(specialJwt, result);
    }

    [Fact]
    public void SdJwt_WithDisclosuresContainingSpecialCharacters_WorksCorrectly()
    {
        // Arrange
        var disclosures = new List<string>
        {
            "disclosure-with-dash",
            "disclosure_with_underscore",
            "disclosure+with+plus"
        };
        var sdJwt = new SdJwt(ValidJwt, disclosures, HashAlgorithm.Sha256);

        // Act
        var combined = sdJwt.ToCombinedFormat();

        // Assert
        Assert.Contains("disclosure-with-dash", combined);
        Assert.Contains("disclosure_with_underscore", combined);
        Assert.Contains("disclosure+with+plus", combined);
    }

    [Fact]
    public void SdJwt_Disclosures_CanBeEnumerated()
    {
        // Arrange
        var disclosures = new List<string> { "d1", "d2", "d3" };
        var sdJwt = new SdJwt(ValidJwt, disclosures, HashAlgorithm.Sha256);

        // Act
        var enumerated = new List<string>();
        foreach (var disclosure in sdJwt.Disclosures)
        {
            enumerated.Add(disclosure);
        }

        // Assert
        Assert.Equal(3, enumerated.Count);
        Assert.Equal(disclosures, enumerated);
    }

    [Fact]
    public void SdJwt_Disclosures_CanBeAccessedByIndex()
    {
        // Arrange
        var disclosures = new List<string> { "first", "second", "third" };
        var sdJwt = new SdJwt(ValidJwt, disclosures, HashAlgorithm.Sha256);

        // Act & Assert
        Assert.Equal("first", sdJwt.Disclosures[0]);
        Assert.Equal("second", sdJwt.Disclosures[1]);
        Assert.Equal("third", sdJwt.Disclosures[2]);
    }

    #endregion
}
