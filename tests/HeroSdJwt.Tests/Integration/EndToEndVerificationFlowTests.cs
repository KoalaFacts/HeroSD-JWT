using HeroSdJwt.Common;
using HeroSdJwt.Issuance;
using HeroSdJwt.Presentation;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using Xunit;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// Integration tests for complete SD-JWT verification flow.
/// Tests the end-to-end flow: Issuance → Presentation → Verification.
/// </summary>
public class EndToEndVerificationFlowTests
{
    private static byte[] GenerateSecureTestKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void CompleteFlow_IssueToVerify_WithAllDisclosures_Succeeds()
    {
        // Arrange - Issuer creates SD-JWT
        var signingKey = GenerateSecureTestKey();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" },
            { "age", 30 },
            { "address", "123 Main St" }
        };

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email", "age", "address" }, // All are selectively disclosable
            signingKey,
            HashAlgorithm.Sha256
        );

        // Act - Holder creates presentation with all disclosures
        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Verify - Verifier validates the presentation
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentationString, signingKey);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.IsValid, "Complete flow verification should succeed");
        Assert.Empty(result.Errors);
        Assert.Contains("email", result.DisclosedClaims.Keys);
        Assert.Contains("age", result.DisclosedClaims.Keys);
        Assert.Contains("address", result.DisclosedClaims.Keys);
    }

    [Fact]
    public void CompleteFlow_IssueToVerify_WithSelectiveDisclosure_Succeeds()
    {
        // Arrange - Issuer creates SD-JWT
        var signingKey = GenerateSecureTestKey();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" },
            { "age", 30 },
            { "ssn", "123-45-6789" },
            { "credit_score", 750 }
        };

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email", "age", "ssn", "credit_score" },
            signingKey,
            HashAlgorithm.Sha256
        );

        // Act - Holder creates presentation with only email and age (not ssn or credit_score)
        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentation(sdJwt, new[] { "email", "age" });
        var presentationString = presenter.FormatPresentation(presentation);

        // Verify
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentationString, signingKey);

        // Assert
        Assert.True(result.IsValid, "Selective disclosure verification should succeed");
        Assert.Contains("email", result.DisclosedClaims.Keys);
        Assert.Contains("age", result.DisclosedClaims.Keys);
        Assert.DoesNotContain("ssn", result.DisclosedClaims.Keys);
        Assert.DoesNotContain("credit_score", result.DisclosedClaims.Keys);
    }

    [Fact]
    public void CompleteFlow_WithTemporalClaims_ValidatesCorrectly()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" },
            { "iat", now.ToUnixTimeSeconds() },
            { "nbf", now.AddMinutes(-5).ToUnixTimeSeconds() },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Act
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(5) };
        var verifier = new SdJwtVerifier(options);
        var result = verifier.VerifyPresentation(presentationString, signingKey);

        // Assert
        Assert.True(result.IsValid, "Verification with valid temporal claims should succeed");
    }

    [Fact]
    public void CompleteFlow_WithExpiredToken_FailsVerification()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" },
            { "exp", now.AddHours(-1).ToUnixTimeSeconds() } // Expired 1 hour ago
        };

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Act
        var verifier = new SdJwtVerifier();
        var result = verifier.TryVerifyPresentation(presentationString, signingKey);

        // Assert
        Assert.False(result.IsValid, "Expired token should fail verification");
        Assert.Contains(ErrorCode.TokenExpired, result.Errors);
    }

    [Fact]
    public void CompleteFlow_WithTamperedDisclosure_FailsVerification()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" },
            { "age", 30 }
        };

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email", "age" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Tamper with a disclosure
        var parts = presentationString.Split('~');
        if (parts.Length > 1)
        {
            var chars = parts[1].ToCharArray();
            chars[^1] = chars[^1] == 'A' ? 'B' : 'A'; // Change last character
            parts[1] = new string(chars);
            presentationString = string.Join("~", parts);
        }

        // Act
        var verifier = new SdJwtVerifier();
        var result = verifier.TryVerifyPresentation(presentationString, signingKey);

        // Assert
        Assert.False(result.IsValid, "Tampered disclosure should fail verification");
        Assert.Contains(ErrorCode.DigestMismatch, result.Errors);
    }

    [Fact]
    public void CompleteFlow_WithWrongSigningKey_FailsVerification()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var wrongKey = GenerateSecureTestKey();

        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" }
        };

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Act - Verify with wrong key
        var verifier = new SdJwtVerifier();
        var result = verifier.TryVerifyPresentation(presentationString, wrongKey);

        // Assert
        Assert.False(result.IsValid, "Verification with wrong key should fail");
        Assert.Contains(ErrorCode.InvalidSignature, result.Errors);
    }

    [Fact]
    public void CompleteFlow_WithDifferentHashAlgorithms_AllSucceed()
    {
        var signingKey = GenerateSecureTestKey();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" }
        };

        var algorithms = new[] { HashAlgorithm.Sha256, HashAlgorithm.Sha384, HashAlgorithm.Sha512 };

        foreach (var algorithm in algorithms)
        {
            // Arrange
            var issuer = new SdJwtIssuer();
            var sdJwt = issuer.CreateSdJwt(
                claims,
                new[] { "email" },
                signingKey,
                algorithm
            );

            var presenter = new SdJwtPresenter();
            var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
            var presentationString = presenter.FormatPresentation(presentation);

            // Act
            var verifier = new SdJwtVerifier();
            var result = verifier.VerifyPresentation(presentationString, signingKey);

            // Assert
            Assert.True(result.IsValid, $"Verification with {algorithm} should succeed");
        }
    }

    [Fact]
    public void CompleteFlow_WithNoSelectiveDisclosures_Succeeds()
    {
        // Arrange - All claims are always-disclosed (in JWT payload)
        var signingKey = GenerateSecureTestKey();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" },
            { "aud", "https://verifier.example.com" }
        };

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            Array.Empty<string>(), // No selectively disclosable claims
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Act
        var verifier = new SdJwtVerifier();
        var result = verifier.VerifyPresentation(presentationString, signingKey);

        // Assert
        Assert.True(result.IsValid, "Verification with no selective disclosures should succeed");
        Assert.Empty(result.DisclosedClaims); // No selectively disclosed claims
    }

    [Fact]
    public void CompleteFlow_WithIssuerValidation_SucceedsWithCorrectIssuer()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" },
            { "email", "user@example.com" }
        };

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Act
        var options = new SdJwtVerificationOptions
        {
            ExpectedIssuer = "https://issuer.example.com"
        };
        var verifier = new SdJwtVerifier(options);
        var result = verifier.VerifyPresentation(presentationString, signingKey);

        // Assert
        Assert.True(result.IsValid, "Verification with correct issuer should succeed");
    }

    [Fact]
    public void CompleteFlow_WithIssuerValidation_FailsWithWrongIssuer()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" },
            { "email", "user@example.com" }
        };

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Act
        var options = new SdJwtVerificationOptions
        {
            ExpectedIssuer = "https://wrong-issuer.example.com"
        };
        var verifier = new SdJwtVerifier(options);
        var result = verifier.TryVerifyPresentation(presentationString, signingKey);

        // Assert
        Assert.False(result.IsValid, "Verification with wrong issuer should fail");
    }
}
