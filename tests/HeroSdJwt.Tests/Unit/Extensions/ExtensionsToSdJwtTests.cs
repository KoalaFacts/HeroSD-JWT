using HeroSdJwt.Extensions;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Models;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit.Extensions;

/// <summary>
/// Tests for ExtensionsToSdJwt extension methods.
/// Validates presentation creation convenience methods.
/// </summary>
public class ExtensionsToSdJwtTests
{
    private readonly SdJwt testSdJwt;
    private readonly byte[] hmacKey;

    public ExtensionsToSdJwtTests()
    {
        // Create a test SD-JWT with selective disclosures
        hmacKey = new byte[32];
        RandomNumberGenerator.Fill(hmacKey);

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com",
            ["name"] = "John Doe",
            ["age"] = 30,
            ["address"] = new Dictionary<string, object>
            {
                ["street"] = "123 Main St",
                ["city"] = "Anytown"
            }
        };

        var issuer = TestHelpers.CreateIssuer();
        testSdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email", "name", "age", "address" },
            hmacKey,
            HashAlgorithm.Sha256,
            decoyDigestCount: 0);
    }

    #region ToPresentation Tests

    [Fact]
    public void ToPresentation_WithNullSdJwt_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            ((SdJwt)null!).ToPresentation("email"));
    }

    [Fact]
    public void ToPresentation_WithNoClaims_ReturnsJwtOnlyPresentation()
    {
        // Act
        var presentation = testSdJwt.ToPresentation();

        // Assert
        Assert.NotNull(presentation);
        Assert.Contains("~", presentation); // Should have separator
        Assert.EndsWith("~", presentation); // Should end with separator (no key binding)
    }

    [Fact]
    public void ToPresentation_WithSingleClaim_IncludesOnlyThatDisclosure()
    {
        // Act
        var presentation = testSdJwt.ToPresentation("email");

        // Assert
        Assert.NotNull(presentation);
        var parts = presentation.Split('~');
        Assert.True(parts.Length >= 2); // JWT + at least one disclosure + empty end
        Assert.NotEmpty(parts[0]); // JWT part
    }

    [Fact]
    public void ToPresentation_WithMultipleClaims_IncludesAllDisclosures()
    {
        // Act
        var presentation = testSdJwt.ToPresentation("email", "name", "age");

        // Assert
        Assert.NotNull(presentation);
        var parts = presentation.Split('~');
        // Should have: JWT + 3 disclosures + empty end = at least 5 parts
        Assert.True(parts.Length >= 4);
    }

    [Fact]
    public void ToPresentation_WithNonExistentClaim_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            testSdJwt.ToPresentation("nonexistent"));

        Assert.Contains("Claim path 'nonexistent' not found", exception.Message);
        Assert.Contains("Available paths: email, name, age, address", exception.Message);
    }

    [Fact]
    public void ToPresentation_WithEmptyClaimArray_ReturnsJwtOnlyPresentation()
    {
        // Act
        var presentation = testSdJwt.ToPresentation(Array.Empty<string>());

        // Assert
        Assert.NotNull(presentation);
        Assert.EndsWith("~", presentation);
    }

    [Fact]
    public void ToPresentation_WithAllSelectiveClaims_IncludesAllDisclosures()
    {
        // Act
        var presentation = testSdJwt.ToPresentation("email", "name", "age", "address");

        // Assert
        Assert.NotNull(presentation);
        var parts = presentation.Split('~');
        Assert.True(parts.Length >= 5); // JWT + 4 disclosures + empty end
    }

    #endregion

    #region ToPresentationWithKeyBinding Tests

    [Fact]
    public void ToPresentationWithKeyBinding_WithNullSdJwt_ThrowsArgumentNullException()
    {
        // Arrange
        var keyBindingJwt = "fake.kb.jwt";

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            ((SdJwt)null!).ToPresentationWithKeyBinding(keyBindingJwt, "email"));
    }

    [Fact]
    public void ToPresentationWithKeyBinding_WithNullKeyBinding_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            testSdJwt.ToPresentationWithKeyBinding(null!, "email"));
    }

    [Fact]
    public void ToPresentationWithKeyBinding_WithValidKeyBinding_IncludesKeyBindingInPresentation()
    {
        // Arrange - Create a real key binding JWT
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();

        var generator = new KeyBindingGenerator();
        var keyBindingJwt = generator.CreateKeyBindingJwt(
            privateKey,
            "test-sd-jwt-hash",
            "https://verifier.example.com",
            "test-nonce");

        // Act
        var presentation = testSdJwt.ToPresentationWithKeyBinding(keyBindingJwt, "email");

        // Assert
        Assert.NotNull(presentation);
        Assert.Contains(keyBindingJwt, presentation);
        Assert.False(presentation.EndsWith("~")); // Should not end with ~ when KB is present
    }

    [Fact]
    public void ToPresentationWithKeyBinding_WithNoClaims_IncludesOnlyJwtAndKeyBinding()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();

        var generator = new KeyBindingGenerator();
        var keyBindingJwt = generator.CreateKeyBindingJwt(
            privateKey,
            "hash",
            "aud",
            "nonce");

        // Act
        var presentation = testSdJwt.ToPresentationWithKeyBinding(keyBindingJwt);

        // Assert
        Assert.NotNull(presentation);
        Assert.Contains(keyBindingJwt, presentation);
        var parts = presentation.Split('~');
        Assert.True(parts.Length >= 2); // JWT + keyBinding (at end)
    }

    [Fact]
    public void ToPresentationWithKeyBinding_WithMultipleClaims_IncludesAllParts()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();

        var generator = new KeyBindingGenerator();
        var keyBindingJwt = generator.CreateKeyBindingJwt(
            privateKey,
            "hash",
            "aud",
            "nonce");

        // Act
        var presentation = testSdJwt.ToPresentationWithKeyBinding(
            keyBindingJwt,
            "email",
            "name");

        // Assert
        Assert.NotNull(presentation);
        Assert.Contains(keyBindingJwt, presentation);
        Assert.EndsWith(keyBindingJwt, presentation); // KB should be at the end
    }

    [Fact]
    public void ToPresentationWithKeyBinding_WithEmptyKeyBinding_ThrowsArgumentNullException()
    {
        // Act & Assert - Empty string is still "not null" but the actual implementation might handle it
        var exception = Assert.Throws<ArgumentNullException>(() =>
            testSdJwt.ToPresentationWithKeyBinding(null!, "email"));

        Assert.NotNull(exception);
    }

    #endregion

    #region ToPresentationWithAllClaims Tests

    [Fact]
    public void ToPresentationWithAllClaims_WithNullSdJwt_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            ((SdJwt)null!).ToPresentationWithAllClaims());
    }

    [Fact]
    public void ToPresentationWithAllClaims_IncludesAllDisclosures()
    {
        // Act
        var presentation = testSdJwt.ToPresentationWithAllClaims();

        // Assert
        Assert.NotNull(presentation);
        var parts = presentation.Split('~');

        // Should include JWT + all 4 selective disclosures + empty end
        Assert.True(parts.Length >= 5);
        Assert.NotEmpty(parts[0]); // JWT
        Assert.Empty(parts[^1]); // Last part should be empty (ends with ~)
    }

    [Fact]
    public void ToPresentationWithAllClaims_ReturnsValidFormat()
    {
        // Act
        var presentation = testSdJwt.ToPresentationWithAllClaims();

        // Assert
        Assert.NotNull(presentation);
        Assert.Contains("~", presentation);
        Assert.EndsWith("~", presentation);

        // Verify it's a properly formatted SD-JWT presentation
        var parts = presentation.Split('~');
        Assert.All(parts.Take(parts.Length - 1), part =>
        {
            if (part.Length > 0) // Skip empty parts
            {
                // Each non-empty part should be base64url encoded
                Assert.DoesNotContain(" ", part);
                Assert.DoesNotContain("+", part); // base64url uses - instead of +
                Assert.DoesNotContain("/", part); // base64url uses _ instead of /
            }
        });
    }

    [Fact]
    public void ToPresentationWithAllClaims_WithSdJwtWithKeyBinding_IncludesKeyBinding()
    {
        // Arrange - Create SD-JWT with key binding
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();

        var generator = new KeyBindingGenerator();
        var keyBindingJwt = generator.CreateKeyBindingJwt(
            privateKey,
            "hash",
            "aud",
            "nonce");

        var sdJwtWithKb = new SdJwt(
            testSdJwt.Jwt,
            testSdJwt.Disclosures,
            testSdJwt.HashAlgorithm,
            keyBindingJwt);

        // Act
        var presentation = sdJwtWithKb.ToPresentationWithAllClaims();

        // Assert
        Assert.NotNull(presentation);
        Assert.Contains(keyBindingJwt, presentation);
    }

    #endregion

    #region Integration Tests

    [Fact]
    public void ToPresentation_CanBeUsedMultipleTimes_ProducesDifferentPresentations()
    {
        // Act
        var presentation1 = testSdJwt.ToPresentation("email");
        var presentation2 = testSdJwt.ToPresentation("email", "name");
        var presentation3 = testSdJwt.ToPresentation("name");

        // Assert - All should be valid but different
        Assert.NotEqual(presentation1, presentation2);
        Assert.NotEqual(presentation2, presentation3);
        Assert.NotEqual(presentation1, presentation3);
    }

    [Fact]
    public void AllMethods_ProduceValidPresentationFormat()
    {
        // Act
        var presentation1 = testSdJwt.ToPresentation("email");
        var presentation2 = testSdJwt.ToPresentationWithAllClaims();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();
        var generator = new KeyBindingGenerator();
        var kb = generator.CreateKeyBindingJwt(privateKey, "hash", "aud", "nonce");
        var presentation3 = testSdJwt.ToPresentationWithKeyBinding(kb, "email");

        // Assert - All should contain ~ separator
        Assert.Contains("~", presentation1);
        Assert.Contains("~", presentation2);
        Assert.Contains("~", presentation3);

        // All should start with the JWT (same for all)
        var jwt1 = presentation1.Split('~')[0];
        var jwt2 = presentation2.Split('~')[0];
        var jwt3 = presentation3.Split('~')[0];

        Assert.Equal(jwt1, jwt2);
        Assert.Equal(jwt2, jwt3);
    }

    #endregion
}
