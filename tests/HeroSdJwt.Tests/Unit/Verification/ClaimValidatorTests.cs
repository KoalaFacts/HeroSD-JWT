using HeroSdJwt.Verification;
using System.Text.Json;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Unit tests for new ClaimValidator().
/// Tests temporal claim validation (exp, nbf, iat) and issuer/audience validation.
/// </summary>
public class ClaimValidatorTests
{
    [Fact]
    public void ValidateTemporalClaims_WithValidClaims_ReturnsTrue()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var payload = CreatePayload(new
        {
            iat = now.ToUnixTimeSeconds(),
            nbf = now.AddMinutes(-5).ToUnixTimeSeconds(),
            exp = now.AddHours(1).ToUnixTimeSeconds()
        });

        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(5) };

        // Act
        var result = new ClaimValidator().ValidateTemporalClaims(payload, options, now);

        // Assert
        Assert.True(result, "Valid temporal claims should pass validation");
    }

    [Fact]
    public void ValidateTemporalClaims_WithExpiredToken_ReturnsFalse()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var payload = CreatePayload(new
        {
            exp = now.AddHours(-1).ToUnixTimeSeconds() // Expired 1 hour ago
        });

        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(5) };

        // Act
        var result = new ClaimValidator().ValidateTemporalClaims(payload, options, now);

        // Assert
        Assert.False(result, "Expired token should fail validation");
    }

    [Fact]
    public void ValidateTemporalClaims_WithExpiredTokenWithinClockSkew_ReturnsTrue()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var payload = CreatePayload(new
        {
            exp = now.AddMinutes(-2).ToUnixTimeSeconds() // Expired 2 minutes ago
        });

        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(5) }; // 5 min tolerance

        // Act
        var result = new ClaimValidator().ValidateTemporalClaims(payload, options, now);

        // Assert
        Assert.True(result, "Token expired within clock skew should pass validation");
    }

    [Fact]
    public void ValidateTemporalClaims_WithNotYetValidToken_ReturnsFalse()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var payload = CreatePayload(new
        {
            nbf = now.AddHours(1).ToUnixTimeSeconds() // Not valid until 1 hour from now
        });

        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(5) };

        // Act
        var result = new ClaimValidator().ValidateTemporalClaims(payload, options, now);

        // Assert
        Assert.False(result, "Not-yet-valid token should fail validation");
    }

    [Fact]
    public void ValidateTemporalClaims_WithNotYetValidTokenWithinClockSkew_ReturnsTrue()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var payload = CreatePayload(new
        {
            nbf = now.AddMinutes(2).ToUnixTimeSeconds() // Valid in 2 minutes
        });

        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(5) }; // 5 min tolerance

        // Act
        var result = new ClaimValidator().ValidateTemporalClaims(payload, options, now);

        // Assert
        Assert.True(result, "Token not-yet-valid within clock skew should pass validation");
    }

    [Fact]
    public void ValidateTemporalClaims_WithNoTemporalClaims_ReturnsTrue()
    {
        // Arrange - Token with no exp, nbf, or iat claims
        var payload = CreatePayload(new { sub = "user123" });
        var options = new SdJwtVerificationOptions();

        // Act
        var result = new ClaimValidator().ValidateTemporalClaims(payload, options);

        // Assert
        Assert.True(result, "Token without temporal claims should pass validation");
    }

    [Fact]
    public void ValidateTemporalClaims_WithInvalidExpFormat_ReturnsFalse()
    {
        // Arrange - exp as string instead of number
        var payload = CreatePayload(new { exp = "not-a-number" });
        var options = new SdJwtVerificationOptions();

        // Act
        var result = new ClaimValidator().ValidateTemporalClaims(payload, options);

        // Assert
        Assert.False(result, "Invalid exp format should fail validation");
    }

    [Fact]
    public void ValidateTemporalClaims_WithInvalidNbfFormat_ReturnsFalse()
    {
        // Arrange - nbf as string instead of number
        var payload = CreatePayload(new { nbf = "invalid" });
        var options = new SdJwtVerificationOptions();

        // Act
        var result = new ClaimValidator().ValidateTemporalClaims(payload, options);

        // Assert
        Assert.False(result, "Invalid nbf format should fail validation");
    }

    [Fact]
    public void ValidateTemporalClaims_WithInvalidIatFormat_ReturnsFalse()
    {
        // Arrange - iat as object instead of number
        var payload = CreatePayload(new { iat = new { invalid = true } });
        var options = new SdJwtVerificationOptions();

        // Act
        var result = new ClaimValidator().ValidateTemporalClaims(payload, options);

        // Assert
        Assert.False(result, "Invalid iat format should fail validation");
    }

    [Fact]
    public void ValidateTemporalClaims_WithZeroClockSkew_EnforcesStrictTiming()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var payload = CreatePayload(new
        {
            exp = now.AddSeconds(-1).ToUnixTimeSeconds() // Expired 1 second ago
        });

        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.Zero };

        // Act
        var result = new ClaimValidator().ValidateTemporalClaims(payload, options, now);

        // Assert
        Assert.False(result, "With zero clock skew, even 1 second expiry should fail");
    }

    [Fact]
    public void ValidateTemporalClaims_WithNullOptions_ThrowsArgumentNullException()
    {
        // Arrange
        var payload = CreatePayload(new { sub = "user123" });

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new ClaimValidator().ValidateTemporalClaims(payload, null!));
    }

    [Fact]
    public void ValidateIssuer_WithMatchingIssuer_ReturnsTrue()
    {
        // Arrange
        var payload = CreatePayload(new { iss = "https://issuer.example.com" });
        var expectedIssuer = "https://issuer.example.com";

        // Act
        var result = new ClaimValidator().ValidateIssuer(payload, expectedIssuer);

        // Assert
        Assert.True(result, "Matching issuer should pass validation");
    }

    [Fact]
    public void ValidateIssuer_WithNonMatchingIssuer_ReturnsFalse()
    {
        // Arrange
        var payload = CreatePayload(new { iss = "https://issuer.example.com" });
        var expectedIssuer = "https://different.example.com";

        // Act
        var result = new ClaimValidator().ValidateIssuer(payload, expectedIssuer);

        // Assert
        Assert.False(result, "Non-matching issuer should fail validation");
    }

    [Fact]
    public void ValidateIssuer_WithNullExpectedIssuer_ReturnsTrue()
    {
        // Arrange - No issuer validation required
        var payload = CreatePayload(new { iss = "https://issuer.example.com" });

        // Act
        var result = new ClaimValidator().ValidateIssuer(payload, null);

        // Assert
        Assert.True(result, "Null expected issuer should skip validation");
    }

    [Fact]
    public void ValidateIssuer_WithMissingIssClaim_ReturnsFalse()
    {
        // Arrange
        var payload = CreatePayload(new { sub = "user123" }); // No iss claim
        var expectedIssuer = "https://issuer.example.com";

        // Act
        var result = new ClaimValidator().ValidateIssuer(payload, expectedIssuer);

        // Assert
        Assert.False(result, "Missing iss claim should fail validation when issuer expected");
    }

    [Fact]
    public void ValidateIssuer_IsCaseSensitive()
    {
        // Arrange
        var payload = CreatePayload(new { iss = "https://Issuer.Example.Com" });
        var expectedIssuer = "https://issuer.example.com"; // Different case

        // Act
        var result = new ClaimValidator().ValidateIssuer(payload, expectedIssuer);

        // Assert
        Assert.False(result, "Issuer validation should be case-sensitive");
    }

    [Fact]
    public void ValidateAudience_WithMatchingAudienceString_ReturnsTrue()
    {
        // Arrange
        var payload = CreatePayload(new { aud = "https://api.example.com" });
        var expectedAudience = "https://api.example.com";

        // Act
        var result = new ClaimValidator().ValidateAudience(payload, expectedAudience);

        // Assert
        Assert.True(result, "Matching audience string should pass validation");
    }

    [Fact]
    public void ValidateAudience_WithMatchingAudienceInArray_ReturnsTrue()
    {
        // Arrange
        var payload = CreatePayload(new
        {
            aud = new[] { "https://api1.example.com", "https://api2.example.com" }
        });
        var expectedAudience = "https://api2.example.com";

        // Act
        var result = new ClaimValidator().ValidateAudience(payload, expectedAudience);

        // Assert
        Assert.True(result, "Matching audience in array should pass validation");
    }

    [Fact]
    public void ValidateAudience_WithNonMatchingAudienceString_ReturnsFalse()
    {
        // Arrange
        var payload = CreatePayload(new { aud = "https://api.example.com" });
        var expectedAudience = "https://different.example.com";

        // Act
        var result = new ClaimValidator().ValidateAudience(payload, expectedAudience);

        // Assert
        Assert.False(result, "Non-matching audience should fail validation");
    }

    [Fact]
    public void ValidateAudience_WithNonMatchingAudienceArray_ReturnsFalse()
    {
        // Arrange
        var payload = CreatePayload(new
        {
            aud = new[] { "https://api1.example.com", "https://api2.example.com" }
        });
        var expectedAudience = "https://api3.example.com";

        // Act
        var result = new ClaimValidator().ValidateAudience(payload, expectedAudience);

        // Assert
        Assert.False(result, "Expected audience not in array should fail validation");
    }

    [Fact]
    public void ValidateAudience_WithNullExpectedAudience_ReturnsTrue()
    {
        // Arrange - No audience validation required
        var payload = CreatePayload(new { aud = "https://api.example.com" });

        // Act
        var result = new ClaimValidator().ValidateAudience(payload, null);

        // Assert
        Assert.True(result, "Null expected audience should skip validation");
    }

    [Fact]
    public void ValidateAudience_WithMissingAudClaim_ReturnsFalse()
    {
        // Arrange
        var payload = CreatePayload(new { sub = "user123" }); // No aud claim
        var expectedAudience = "https://api.example.com";

        // Act
        var result = new ClaimValidator().ValidateAudience(payload, expectedAudience);

        // Assert
        Assert.False(result, "Missing aud claim should fail validation when audience expected");
    }

    [Fact]
    public void ValidateAudience_IsCaseSensitive()
    {
        // Arrange
        var payload = CreatePayload(new { aud = "https://API.Example.Com" });
        var expectedAudience = "https://api.example.com"; // Different case

        // Act
        var result = new ClaimValidator().ValidateAudience(payload, expectedAudience);

        // Assert
        Assert.False(result, "Audience validation should be case-sensitive");
    }

    [Fact]
    public void ValidateAudience_WithInvalidAudFormat_ReturnsFalse()
    {
        // Arrange - aud as number instead of string or array
        var payload = CreatePayload(new { aud = 12345 });
        var expectedAudience = "https://api.example.com";

        // Act
        var result = new ClaimValidator().ValidateAudience(payload, expectedAudience);

        // Assert
        Assert.False(result, "Invalid aud format should fail validation");
    }

    // Helper method to create a JSON payload
    private static JsonElement CreatePayload(object claims)
    {
        var json = JsonSerializer.Serialize(claims);
        return JsonDocument.Parse(json).RootElement;
    }
}
