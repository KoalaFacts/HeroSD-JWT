using HeroSdJwt.Tests;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using Xunit;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// Contract tests for SdJwtPresenter API.
/// These tests define the expected behavior for creating presentations.
/// Written BEFORE implementation (TDD).
/// </summary>
public class SdJwtPresenterContractTests
{
    [Fact]
    public void CreatePresentation_WithSelectedClaims_ReturnsValidPresentation()
    {
        // Arrange
        var sdJwt = CreateTestSdJwt();
        var presenter = new SdJwtPresenter();
        var selectedClaims = new[] { "email" }; // Only disclose email, not age

        // Act
        var presentation = presenter.CreatePresentation(sdJwt, selectedClaims);

        // Assert
        Assert.NotNull(presentation);
        Assert.Equal(sdJwt.Jwt, presentation.Jwt);
        Assert.Single(presentation.SelectedDisclosures); // Only email disclosure
        Assert.Null(presentation.KeyBindingJwt); // No key binding by default
    }

    [Fact]
    public void CreatePresentation_WithAllClaims_IncludesAllDisclosures()
    {
        // Arrange
        var sdJwt = CreateTestSdJwt();
        var presenter = new SdJwtPresenter();
        var selectedClaims = new[] { "email", "age" }; // All selectively disclosable claims

        // Act
        var presentation = presenter.CreatePresentation(sdJwt, selectedClaims);

        // Assert
        Assert.NotNull(presentation);
        Assert.Equal(2, presentation.SelectedDisclosures.Count); // Both disclosures
    }

    [Fact]
    public void CreatePresentation_WithNoClaims_ReturnsEmptyDisclosures()
    {
        // Arrange
        var sdJwt = CreateTestSdJwt();
        var presenter = new SdJwtPresenter();
        var selectedClaims = Array.Empty<string>(); // No claims disclosed

        // Act
        var presentation = presenter.CreatePresentation(sdJwt, selectedClaims);

        // Assert
        Assert.NotNull(presentation);
        Assert.Empty(presentation.SelectedDisclosures);
    }

    [Fact]
    public void CreatePresentation_WithInvalidClaimName_ThrowsArgumentException()
    {
        // Arrange
        var sdJwt = CreateTestSdJwt();
        var presenter = new SdJwtPresenter();
        var selectedClaims = new[] { "nonexistent" }; // Claim that wasn't in original SD-JWT

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            presenter.CreatePresentation(sdJwt, selectedClaims));
    }

    [Fact]
    public void FormatPresentation_ReturnsTildeSeparatedString()
    {
        // Arrange
        var sdJwt = CreateTestSdJwt();
        var presenter = new SdJwtPresenter();
        var selectedClaims = new[] { "email" };
        var presentation = presenter.CreatePresentation(sdJwt, selectedClaims);

        // Act
        var formatted = presenter.FormatPresentation(presentation);

        // Assert
        Assert.NotNull(formatted);
        Assert.Contains("~", formatted); // Contains tilde separator
        Assert.StartsWith(sdJwt.Jwt, formatted); // Starts with JWT
        Assert.EndsWith("~", formatted); // Ends with tilde (empty key binding slot)
    }

    [Fact]
    public void FormatPresentation_WithNoDisclosures_HasCorrectFormat()
    {
        // Arrange
        var sdJwt = CreateTestSdJwt();
        var presenter = new SdJwtPresenter();
        var selectedClaims = Array.Empty<string>();
        var presentation = presenter.CreatePresentation(sdJwt, selectedClaims);

        // Act
        var formatted = presenter.FormatPresentation(presentation);

        // Assert
        // Format should be: JWT~~  (JWT, no disclosures, empty key binding)
        Assert.Equal($"{sdJwt.Jwt}~~", formatted);
    }

    [Fact]
    public void CreatePresentationWithAllClaims_ConvenienceMethod_IncludesAllDisclosures()
    {
        // Arrange
        var sdJwt = CreateTestSdJwt();
        var presenter = new SdJwtPresenter();

        // Act
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);

        // Assert
        Assert.NotNull(presentation);
        Assert.Equal(2, presentation.SelectedDisclosures.Count); // All original disclosures
    }

    // Helper method to create a test SD-JWT
    private static SdJwt CreateTestSdJwt()
    {
        var issuer = TestHelpers.CreateIssuer();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" },
            { "age", 30 }
        };

        var selectivelyDisclosableClaims = new[] { "email", "age" };
        var signingKey = new byte[32]; // Dummy key
        var hashAlgorithm = HashAlgorithm.Sha256;

        return issuer.CreateSdJwt(claims, selectivelyDisclosableClaims, signingKey, hashAlgorithm);
    }
}
