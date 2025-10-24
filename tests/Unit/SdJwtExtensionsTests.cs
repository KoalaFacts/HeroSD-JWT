using HeroSdJwt.Common;
using HeroSdJwt.Core;
using HeroSdJwt.Issuance;
using HeroSdJwt.Verification;
using Xunit;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for SdJwtExtensions convenience methods.
/// </summary>
public class SdJwtExtensionsTests
{
    private readonly IKeyGenerator keyGenerator = KeyGenerator.Instance;

    [Fact]
    public void ToPresentation_WithSelectedClaims_ReturnsValidPresentation()
    {
        // Arrange
        var key = keyGenerator.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com",
            ["age"] = 30
        };

        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email", "age")
            .SignWithHmac(key)
            .Build();

        // Act
        var presentation = sdJwt.ToPresentation("email");

        // Assert
        Assert.NotNull(presentation);
        Assert.Contains("~", presentation); // SD-JWT presentation format
        Assert.EndsWith("~", presentation); // Should end with tilde
    }

    [Fact]
    public void ToPresentation_CanBeVerified()
    {
        // Arrange
        var key = keyGenerator.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email")
            .SignWithHmac(key)
            .Build();

        var presentation = sdJwt.ToPresentation("email");

        // Act
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, key);

        // Assert
        Assert.True(result.IsValid);
        Assert.Contains("email", result.DisclosedClaims.Keys);
    }

    [Fact]
    public void ToPresentationWithAllClaims_RevealsEverything()
    {
        // Arrange
        var key = keyGenerator.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com",
            ["age"] = 30,
            ["name"] = "Alice"
        };

        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email", "age", "name")
            .SignWithHmac(key)
            .Build();

        // Act
        var presentation = sdJwt.ToPresentationWithAllClaims();

        // Assert
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, key);

        Assert.True(result.IsValid);
        Assert.Contains("email", result.DisclosedClaims.Keys);
        Assert.Contains("age", result.DisclosedClaims.Keys);
        Assert.Contains("name", result.DisclosedClaims.Keys);
    }

    [Fact]
    public void ToPresentation_WithNullSdJwt_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            ((SdJwt)null!).ToPresentation("email"));
    }

    [Fact]
    public void ToPresentationWithKeyBinding_WithNullSdJwt_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            ((SdJwt)null!).ToPresentationWithKeyBinding("kbjwt", "email"));
    }

    [Fact]
    public void ToPresentationWithKeyBinding_WithNullKeyBinding_ThrowsArgumentNullException()
    {
        // Arrange
        var key = keyGenerator.GenerateHmacKey();
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };
        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .SignWithHmac(key)
            .Build();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            sdJwt.ToPresentationWithKeyBinding(null!, "email"));
    }

    [Fact]
    public void ToPresentation_WithNoClaimsToReveal_ReturnsJwtOnly()
    {
        // Arrange
        var key = keyGenerator.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email")
            .SignWithHmac(key)
            .Build();

        // Act - Don't reveal any selective claims
        var presentation = sdJwt.ToPresentation();

        // Assert
        Assert.NotNull(presentation);
        Assert.EndsWith("~", presentation);
        // Should be JWT~~~ (no disclosures)
    }

    [Fact]
    public void ExtensionMethods_WorkWithBuilderAPI()
    {
        // Arrange & Act - Fluent chain from builder to presentation
        var key = keyGenerator.GenerateHmacKey();
        var presentation = SdJwtBuilder.Create()
            .WithClaim("sub", "user123")
            .WithClaim("email", "user@example.com")
            .WithClaim("age", 30)
            .MakeSelective("email", "age")
            .SignWithHmac(key)
            .Build()
            .ToPresentation("email"); // Extension method

        // Assert
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentation, key);

        Assert.True(result.IsValid);
        Assert.Contains("email", result.DisclosedClaims.Keys);
        Assert.DoesNotContain("age", result.DisclosedClaims.Keys); // Not revealed
    }
}
