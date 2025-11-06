using HeroSdJwt.Presentation;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Presentation;

/// <summary>
/// Tests for SdJwtPresentation model class.
/// Validates construction, property access, and ToString formatting.
/// </summary>
public class SdJwtPresentationTests
{
    private const string TestJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    private const string TestKeyBindingJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE2ODkzNDcyMDB9.signature";

    #region Constructor Tests

    [Fact]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        // Arrange
        var disclosures = new[] { "disclosure1", "disclosure2", "disclosure3" };

        // Act
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Assert
        Assert.NotNull(presentation);
        Assert.Equal(TestJwt, presentation.Jwt);
        Assert.Equal(3, presentation.SelectedDisclosures.Count);
        Assert.Null(presentation.KeyBindingJwt);
    }

    [Fact]
    public void Constructor_WithKeyBinding_StoresKeyBinding()
    {
        // Arrange
        var disclosures = new[] { "disclosure1" };

        // Act
        var presentation = new SdJwtPresentation(TestJwt, disclosures, TestKeyBindingJwt);

        // Assert
        Assert.Equal(TestKeyBindingJwt, presentation.KeyBindingJwt);
    }

    [Fact]
    public void Constructor_WithNullJwt_ThrowsArgumentNullException()
    {
        // Arrange
        var disclosures = new[] { "disclosure1" };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new SdJwtPresentation(null!, disclosures));
    }

    [Fact]
    public void Constructor_WithNullDisclosures_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new SdJwtPresentation(TestJwt, null!));
    }

    [Fact]
    public void Constructor_WithEmptyDisclosures_CreatesInstanceWithEmptyList()
    {
        // Arrange
        var emptyDisclosures = Array.Empty<string>();

        // Act
        var presentation = new SdJwtPresentation(TestJwt, emptyDisclosures);

        // Assert
        Assert.NotNull(presentation);
        Assert.Empty(presentation.SelectedDisclosures);
    }

    [Fact]
    public void Constructor_WithSingleDisclosure_StoresSingleDisclosure()
    {
        // Arrange
        var disclosures = new[] { "single-disclosure" };

        // Act
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Assert
        Assert.Single(presentation.SelectedDisclosures);
        Assert.Equal("single-disclosure", presentation.SelectedDisclosures[0]);
    }

    [Fact]
    public void Constructor_WithMultipleDisclosures_StoresAllDisclosures()
    {
        // Arrange
        var disclosures = new[] { "disclosure1", "disclosure2", "disclosure3", "disclosure4" };

        // Act
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Assert
        Assert.Equal(4, presentation.SelectedDisclosures.Count);
        Assert.Equal("disclosure1", presentation.SelectedDisclosures[0]);
        Assert.Equal("disclosure2", presentation.SelectedDisclosures[1]);
        Assert.Equal("disclosure3", presentation.SelectedDisclosures[2]);
        Assert.Equal("disclosure4", presentation.SelectedDisclosures[3]);
    }

    #endregion

    #region Property Tests

    [Fact]
    public void Jwt_AfterConstruction_ReturnsCorrectValue()
    {
        // Arrange
        var disclosures = new[] { "disclosure1" };
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Act
        var jwt = presentation.Jwt;

        // Assert
        Assert.Equal(TestJwt, jwt);
    }

    [Fact]
    public void SelectedDisclosures_IsReadOnly()
    {
        // Arrange
        var disclosures = new[] { "disclosure1", "disclosure2" };
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Act
        var selectedDisclosures = presentation.SelectedDisclosures;

        // Assert
        Assert.IsAssignableFrom<IReadOnlyList<string>>(selectedDisclosures);
    }

    [Fact]
    public void SelectedDisclosures_ModifyingOriginalList_DoesNotAffectPresentation()
    {
        // Arrange
        var disclosures = new List<string> { "disclosure1", "disclosure2" };
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Act - Modify original list
        disclosures.Add("disclosure3");
        disclosures[0] = "modified";

        // Assert - Presentation should not be affected
        Assert.Equal(2, presentation.SelectedDisclosures.Count);
        Assert.Equal("disclosure1", presentation.SelectedDisclosures[0]);
        Assert.Equal("disclosure2", presentation.SelectedDisclosures[1]);
    }

    [Fact]
    public void KeyBindingJwt_WhenNotProvided_ReturnsNull()
    {
        // Arrange
        var disclosures = new[] { "disclosure1" };
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Act & Assert
        Assert.Null(presentation.KeyBindingJwt);
    }

    [Fact]
    public void KeyBindingJwt_WhenProvided_ReturnsCorrectValue()
    {
        // Arrange
        var disclosures = new[] { "disclosure1" };
        var presentation = new SdJwtPresentation(TestJwt, disclosures, TestKeyBindingJwt);

        // Act & Assert
        Assert.Equal(TestKeyBindingJwt, presentation.KeyBindingJwt);
    }

    #endregion

    #region ToString Tests

    [Fact]
    public void ToString_WithNoKeyBinding_ReturnsCorrectFormat()
    {
        // Arrange
        var disclosures = new[] { "disclosure1", "disclosure2", "disclosure3" };
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Act
        var result = presentation.ToString();

        // Assert
        Assert.Equal("SdJwtPresentation(Disclosures=3, no KB)", result);
    }

    [Fact]
    public void ToString_WithKeyBinding_ReturnsCorrectFormat()
    {
        // Arrange
        var disclosures = new[] { "disclosure1", "disclosure2" };
        var presentation = new SdJwtPresentation(TestJwt, disclosures, TestKeyBindingJwt);

        // Act
        var result = presentation.ToString();

        // Assert
        Assert.Equal("SdJwtPresentation(Disclosures=2, with KB)", result);
    }

    [Fact]
    public void ToString_WithZeroDisclosures_ReturnsZeroCount()
    {
        // Arrange
        var presentation = new SdJwtPresentation(TestJwt, Array.Empty<string>());

        // Act
        var result = presentation.ToString();

        // Assert
        Assert.Equal("SdJwtPresentation(Disclosures=0, no KB)", result);
    }

    [Fact]
    public void ToString_WithSingleDisclosure_ReturnsSingleCount()
    {
        // Arrange
        var disclosures = new[] { "disclosure1" };
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Act
        var result = presentation.ToString();

        // Assert
        Assert.Equal("SdJwtPresentation(Disclosures=1, no KB)", result);
    }

    [Fact]
    public void ToString_WithManyDisclosures_ReturnsCorrectCount()
    {
        // Arrange
        var disclosures = new[] { "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10" };
        var presentation = new SdJwtPresentation(TestJwt, disclosures, TestKeyBindingJwt);

        // Act
        var result = presentation.ToString();

        // Assert
        Assert.Equal("SdJwtPresentation(Disclosures=10, with KB)", result);
    }

    [Fact]
    public void ToString_CalledMultipleTimes_ReturnsConsistentResult()
    {
        // Arrange
        var disclosures = new[] { "disclosure1", "disclosure2" };
        var presentation = new SdJwtPresentation(TestJwt, disclosures, TestKeyBindingJwt);

        // Act
        var result1 = presentation.ToString();
        var result2 = presentation.ToString();
        var result3 = presentation.ToString();

        // Assert
        Assert.Equal(result1, result2);
        Assert.Equal(result2, result3);
    }

    #endregion

    #region Edge Case Tests

    [Fact]
    public void Constructor_WithDuplicateDisclosures_StoresAllDuplicates()
    {
        // Arrange
        var disclosures = new[] { "disclosure1", "disclosure1", "disclosure1" };

        // Act
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Assert
        Assert.Equal(3, presentation.SelectedDisclosures.Count);
        Assert.All(presentation.SelectedDisclosures, d => Assert.Equal("disclosure1", d));
    }

    [Fact]
    public void Constructor_WithEmptyStringJwt_CreatesInstance()
    {
        // Arrange
        var disclosures = new[] { "disclosure1" };

        // Act
        var presentation = new SdJwtPresentation(string.Empty, disclosures);

        // Assert
        Assert.Equal(string.Empty, presentation.Jwt);
    }

    [Fact]
    public void Constructor_WithEmptyStringKeyBinding_StoresEmptyString()
    {
        // Arrange
        var disclosures = new[] { "disclosure1" };

        // Act
        var presentation = new SdJwtPresentation(TestJwt, disclosures, string.Empty);

        // Assert
        Assert.Equal(string.Empty, presentation.KeyBindingJwt);
    }

    [Fact]
    public void Constructor_WithWhitespaceJwt_CreatesInstance()
    {
        // Arrange
        var disclosures = new[] { "disclosure1" };

        // Act
        var presentation = new SdJwtPresentation("   ", disclosures);

        // Assert
        Assert.Equal("   ", presentation.Jwt);
    }

    [Fact]
    public void Constructor_WithDisclosuresContainingEmptyStrings_StoresEmptyStrings()
    {
        // Arrange
        var disclosures = new[] { "disclosure1", "", "disclosure2", "" };

        // Act
        var presentation = new SdJwtPresentation(TestJwt, disclosures);

        // Assert
        Assert.Equal(4, presentation.SelectedDisclosures.Count);
        Assert.Equal("", presentation.SelectedDisclosures[1]);
        Assert.Equal("", presentation.SelectedDisclosures[3]);
    }

    #endregion
}
