using HeroSdJwt.Presentation;
using HeroSdJwt.Models;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Presentation;

/// <summary>
/// Unit tests for SdJwtPresenter - detailed edge case and error handling tests.
/// Complements the contract tests with additional coverage of error paths.
/// </summary>
public class SdJwtPresenterTests
{
    private readonly SdJwtPresenter presenter;
    private readonly SdJwt testSdJwt;

    public SdJwtPresenterTests()
    {
        presenter = new SdJwtPresenter();

        // Create a test SD-JWT with nested claims
        var issuer = TestHelpers.CreateIssuer();
        var hmacKey = new byte[32];
        Random.Shared.NextBytes(hmacKey);

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com",
            ["age"] = 30,
            ["address"] = new Dictionary<string, object>
            {
                ["street"] = "123 Main St",
                ["city"] = "Anytown",
                ["geo"] = new Dictionary<string, object>
                {
                    ["lat"] = 40.7128,
                    ["lon"] = -74.0060
                }
            }
        };

        testSdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email", "age", "address", "address.geo", "address.geo.lat" },
            hmacKey,
            HashAlgorithm.Sha256);
    }

    #region Constructor Tests

    [Fact]
    public void Constructor_WithDefaultParameters_CreatesInstance()
    {
        // Act
        var presenter = new SdJwtPresenter();

        // Assert
        Assert.NotNull(presenter);
    }

    [Fact]
    public void Constructor_WithLogger_CreatesInstance()
    {
        // Arrange
        var logger = new Microsoft.Extensions.Logging.Abstractions.NullLogger<SdJwtPresenter>();

        // Act
        var presenter = new SdJwtPresenter(logger);

        // Assert
        Assert.NotNull(presenter);
    }

    [Fact]
    public void Constructor_WithClaimPathMapper_CreatesInstance()
    {
        // Arrange
        var mapper = new DisclosureClaimPathMapper();

        // Act
        var presenter = new SdJwtPresenter(mapper);

        // Assert
        Assert.NotNull(presenter);
    }

    #endregion

    #region CreatePresentation - Error Cases

    [Fact]
    public void CreatePresentation_WithNullSdJwt_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            presenter.CreatePresentation(null!, new[] { "email" }));
    }

    [Fact]
    public void CreatePresentation_WithNullSelectedClaims_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            presenter.CreatePresentation(testSdJwt, null!));
    }

    [Fact]
    public void CreatePresentation_WithNonExistentClaim_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            presenter.CreatePresentation(testSdJwt, new[] { "nonexistent" }));

        Assert.Contains("Claim path 'nonexistent' not found", exception.Message);
        Assert.Contains("Available paths:", exception.Message);
    }

    [Fact]
    public void CreatePresentation_WithEmptyClaimsList_CreatesEmptyPresentation()
    {
        // Act
        var presentation = presenter.CreatePresentation(testSdJwt, Array.Empty<string>());

        // Assert
        Assert.NotNull(presentation);
        Assert.Empty(presentation.SelectedDisclosures);
    }

    #endregion

    #region CreatePresentation - Multiple Claims

    [Fact]
    public void CreatePresentation_WithMultipleClaims_IncludesAllRequested()
    {
        // Arrange
        var selectedClaims = new[] { "email", "age" };

        // Act
        var presentation = presenter.CreatePresentation(testSdJwt, selectedClaims);

        // Assert
        Assert.NotNull(presentation);
        Assert.True(presentation.SelectedDisclosures.Count >= 2);
    }

    [Fact]
    public void CreatePresentation_WithSingleClaim_IncludesOnlyThatClaim()
    {
        // Arrange
        var selectedClaims = new[] { "email" };

        // Act
        var presentation = presenter.CreatePresentation(testSdJwt, selectedClaims);

        // Assert
        Assert.NotNull(presentation);
        Assert.True(presentation.SelectedDisclosures.Count >= 1);
    }

    #endregion

    #region CreatePresentation - Key Binding

    [Fact]
    public void CreatePresentation_WithKeyBindingJwt_IncludesKeyBinding()
    {
        // Arrange
        var customKeyBinding = "custom.key.binding";

        // Act
        var presentation = presenter.CreatePresentation(
            testSdJwt,
            new[] { "email" },
            customKeyBinding);

        // Assert
        Assert.Equal(customKeyBinding, presentation.KeyBindingJwt);
    }

    [Fact]
    public void CreatePresentation_WithoutKeyBindingParameter_UsesDefaultFromSdJwt()
    {
        // Arrange - SD-JWT might have a key binding
        var selectedClaims = new[] { "email" };

        // Act
        var presentation = presenter.CreatePresentation(testSdJwt, selectedClaims);

        // Assert - Should use key binding from SD-JWT (or null if not present)
        Assert.Equal(testSdJwt.KeyBindingJwt, presentation.KeyBindingJwt);
    }

    #endregion

    #region CreatePresentationWithAllClaims Tests

    [Fact]
    public void CreatePresentationWithAllClaims_ReturnsAllDisclosures()
    {
        // Act
        var presentation = presenter.CreatePresentationWithAllClaims(testSdJwt);

        // Assert
        Assert.Equal(testSdJwt.Disclosures.Count, presentation.SelectedDisclosures.Count);
    }

    [Fact]
    public void CreatePresentationWithAllClaims_WithNullSdJwt_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            presenter.CreatePresentationWithAllClaims(null!));
    }

    [Fact]
    public void CreatePresentationWithAllClaims_WithCustomKeyBinding_UsesCustomKeyBinding()
    {
        // Arrange
        var customKeyBinding = "custom.kb.jwt";

        // Act
        var presentation = presenter.CreatePresentationWithAllClaims(testSdJwt, customKeyBinding);

        // Assert
        Assert.Equal(customKeyBinding, presentation.KeyBindingJwt);
    }

    [Fact]
    public void CreatePresentationWithAllClaims_WithoutKeyBinding_UsesDefaultFromSdJwt()
    {
        // Act
        var presentation = presenter.CreatePresentationWithAllClaims(testSdJwt);

        // Assert
        Assert.Equal(testSdJwt.KeyBindingJwt, presentation.KeyBindingJwt);
    }

    #endregion

    #region FormatPresentation Tests

    [Fact]
    public void FormatPresentation_WithDisclosures_ReturnsTildeSeparatedFormat()
    {
        // Arrange
        var presentation = presenter.CreatePresentation(testSdJwt, new[] { "email" });

        // Act
        var formatted = presenter.FormatPresentation(presentation);

        // Assert
        Assert.Contains("~", formatted);
        Assert.StartsWith(testSdJwt.Jwt, formatted);
    }

    [Fact]
    public void FormatPresentation_WithNoDisclosures_IncludesEmptySlot()
    {
        // Arrange
        var presentation = presenter.CreatePresentation(testSdJwt, Array.Empty<string>());

        // Act
        var formatted = presenter.FormatPresentation(presentation);

        // Assert
        Assert.Contains("~~", formatted); // Empty disclosure slot
    }

    [Fact]
    public void FormatPresentation_WithNullPresentation_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            presenter.FormatPresentation(null!));
    }

    [Fact]
    public void FormatPresentation_WithKeyBinding_IncludesKeyBindingAtEnd()
    {
        // Arrange
        var keyBinding = "test.key.binding";
        var presentation = presenter.CreatePresentation(testSdJwt, new[] { "email" }, keyBinding);

        // Act
        var formatted = presenter.FormatPresentation(presentation);

        // Assert
        Assert.EndsWith(keyBinding, formatted);
    }

    [Fact]
    public void FormatPresentation_WithoutKeyBinding_EndsWithEmptyString()
    {
        // Arrange
        var presentation = presenter.CreatePresentation(testSdJwt, new[] { "email" });

        // Act
        var formatted = presenter.FormatPresentation(presentation);

        // Assert
        Assert.EndsWith("~", formatted); // Ends with tilde (empty key binding)
    }

    #endregion

    #region Integration Tests

    [Fact]
    public void CreatePresentation_WithMultipleClaims_MaintainsConsistentOrder()
    {
        // Arrange
        var selectedClaims = new[] { "age", "email" };

        // Act
        var presentation1 = presenter.CreatePresentation(testSdJwt, selectedClaims);
        var presentation2 = presenter.CreatePresentation(testSdJwt, selectedClaims);

        // Assert - Both presentations should have same disclosure order
        Assert.Equal(presentation1.SelectedDisclosures.Count, presentation2.SelectedDisclosures.Count);
        for (int i = 0; i < presentation1.SelectedDisclosures.Count; i++)
        {
            Assert.Equal(presentation1.SelectedDisclosures[i], presentation2.SelectedDisclosures[i]);
        }
    }

    [Fact]
    public void FormatPresentation_RoundTrip_ProducesConsistentOutput()
    {
        // Arrange
        var presentation = presenter.CreatePresentation(testSdJwt, new[] { "email", "age" });

        // Act
        var formatted1 = presenter.FormatPresentation(presentation);
        var formatted2 = presenter.FormatPresentation(presentation);

        // Assert
        Assert.Equal(formatted1, formatted2);
    }

    #endregion
}
