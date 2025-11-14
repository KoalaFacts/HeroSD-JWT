using HeroSdJwt.Verification;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Tests for SdJwtVerificationOptions configuration class.
/// Validates property initialization, validation logic, and edge cases.
/// </summary>
public class SdJwtVerificationOptionsTests
{
    #region Default Values Tests

    [Fact]
    public void Constructor_WithDefaults_SetsExpectedValues()
    {
        // Act
        var options = new SdJwtVerificationOptions();

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(5), options.ClockSkew);
        Assert.False(options.RequireKeyBinding);
        Assert.Null(options.ExpectedIssuer);
        Assert.Null(options.ExpectedAudience);
        Assert.Null(options.ExpectedHashAlgorithm);
        Assert.Null(options.ExpectedNonce);
    }

    #endregion

    #region ClockSkew Tests

    [Fact]
    public void ClockSkew_WithZero_IsValid()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.Zero };

        // Act & Assert
        Assert.Equal(TimeSpan.Zero, options.ClockSkew);
        options.Validate(); // Should not throw
    }

    [Fact]
    public void ClockSkew_WithOneMinute_IsValid()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(1) };

        // Act & Assert
        Assert.Equal(TimeSpan.FromMinutes(1), options.ClockSkew);
        options.Validate(); // Should not throw
    }

    [Fact]
    public void ClockSkew_WithMaximumValue_IsValid()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(5) };

        // Act & Assert
        Assert.Equal(TimeSpan.FromMinutes(5), options.ClockSkew);
        options.Validate(); // Should not throw
    }

    [Fact]
    public void ClockSkew_WithNegativeValue_ThrowsOnValidate()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(-1) };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => options.Validate());
        Assert.Contains("cannot be negative", exception.Message);
        Assert.Equal("ClockSkew", exception.ParamName);
    }

    [Fact]
    public void ClockSkew_ExceedingMaximum_ThrowsOnValidate()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(6) };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => options.Validate());
        Assert.Contains("cannot exceed 5 minutes", exception.Message);
        Assert.Equal("ClockSkew", exception.ParamName);
    }

    [Fact]
    public void ClockSkew_JustOverMaximum_ThrowsOnValidate()
    {
        // Arrange
        var options = new SdJwtVerificationOptions
        {
            ClockSkew = TimeSpan.FromMinutes(5).Add(TimeSpan.FromSeconds(1))
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => options.Validate());
        Assert.Contains("cannot exceed 5 minutes", exception.Message);
    }

    [Fact]
    public void ClockSkew_WithSeconds_IsValid()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromSeconds(30) };

        // Act & Assert
        Assert.Equal(TimeSpan.FromSeconds(30), options.ClockSkew);
        options.Validate();
    }

    [Fact]
    public void ClockSkew_WithMilliseconds_IsValid()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMilliseconds(500) };

        // Act & Assert
        Assert.Equal(TimeSpan.FromMilliseconds(500), options.ClockSkew);
        options.Validate();
    }

    #endregion

    #region RequireKeyBinding Tests

    [Fact]
    public void RequireKeyBinding_SetToTrue_StoresValue()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { RequireKeyBinding = true };

        // Act & Assert
        Assert.True(options.RequireKeyBinding);
        options.Validate();
    }

    [Fact]
    public void RequireKeyBinding_SetToFalse_StoresValue()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { RequireKeyBinding = false };

        // Act & Assert
        Assert.False(options.RequireKeyBinding);
        options.Validate();
    }

    #endregion

    #region ExpectedIssuer Tests

    [Fact]
    public void ExpectedIssuer_WithValidValue_StoresValue()
    {
        // Arrange
        var issuer = "https://issuer.example.com";
        var options = new SdJwtVerificationOptions { ExpectedIssuer = issuer };

        // Act & Assert
        Assert.Equal(issuer, options.ExpectedIssuer);
        options.Validate();
    }

    [Fact]
    public void ExpectedIssuer_WithNull_StoresNull()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ExpectedIssuer = null };

        // Act & Assert
        Assert.Null(options.ExpectedIssuer);
        options.Validate();
    }

    [Fact]
    public void ExpectedIssuer_WithEmptyString_StoresEmptyString()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ExpectedIssuer = string.Empty };

        // Act & Assert
        Assert.Equal(string.Empty, options.ExpectedIssuer);
        options.Validate();
    }

    #endregion

    #region ExpectedAudience Tests

    [Fact]
    public void ExpectedAudience_WithValidValue_StoresValue()
    {
        // Arrange
        var audience = "https://verifier.example.com";
        var options = new SdJwtVerificationOptions { ExpectedAudience = audience };

        // Act & Assert
        Assert.Equal(audience, options.ExpectedAudience);
        options.Validate();
    }

    [Fact]
    public void ExpectedAudience_WithNull_StoresNull()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ExpectedAudience = null };

        // Act & Assert
        Assert.Null(options.ExpectedAudience);
        options.Validate();
    }

    [Fact]
    public void ExpectedAudience_WithEmptyString_StoresEmptyString()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ExpectedAudience = string.Empty };

        // Act & Assert
        Assert.Equal(string.Empty, options.ExpectedAudience);
        options.Validate();
    }

    #endregion

    #region ExpectedHashAlgorithm Tests

    [Fact]
    public void ExpectedHashAlgorithm_WithSha256_StoresValue()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ExpectedHashAlgorithm = HashAlgorithm.Sha256 };

        // Act & Assert
        Assert.Equal(HashAlgorithm.Sha256, options.ExpectedHashAlgorithm);
        options.Validate();
    }

    [Fact]
    public void ExpectedHashAlgorithm_WithSha384_StoresValue()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ExpectedHashAlgorithm = HashAlgorithm.Sha384 };

        // Act & Assert
        Assert.Equal(HashAlgorithm.Sha384, options.ExpectedHashAlgorithm);
        options.Validate();
    }

    [Fact]
    public void ExpectedHashAlgorithm_WithSha512_StoresValue()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ExpectedHashAlgorithm = HashAlgorithm.Sha512 };

        // Act & Assert
        Assert.Equal(HashAlgorithm.Sha512, options.ExpectedHashAlgorithm);
        options.Validate();
    }

    [Fact]
    public void ExpectedHashAlgorithm_WithNull_StoresNull()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ExpectedHashAlgorithm = null };

        // Act & Assert
        Assert.Null(options.ExpectedHashAlgorithm);
        options.Validate();
    }

    #endregion

    #region ExpectedNonce Tests

    [Fact]
    public void ExpectedNonce_WithValidValue_StoresValue()
    {
        // Arrange
        var nonce = "nonce-12345";
        var options = new SdJwtVerificationOptions { ExpectedNonce = nonce };

        // Act & Assert
        Assert.Equal(nonce, options.ExpectedNonce);
        options.Validate();
    }

    [Fact]
    public void ExpectedNonce_WithNull_StoresNull()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ExpectedNonce = null };

        // Act & Assert
        Assert.Null(options.ExpectedNonce);
        options.Validate();
    }

    [Fact]
    public void ExpectedNonce_WithEmptyString_StoresEmptyString()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ExpectedNonce = string.Empty };

        // Act & Assert
        Assert.Equal(string.Empty, options.ExpectedNonce);
        options.Validate();
    }

    [Fact]
    public void ExpectedNonce_WithLongValue_StoresValue()
    {
        // Arrange
        var nonce = new string('a', 1000);
        var options = new SdJwtVerificationOptions { ExpectedNonce = nonce };

        // Act & Assert
        Assert.Equal(nonce, options.ExpectedNonce);
        options.Validate();
    }

    #endregion

    #region Combined Configuration Tests

    [Fact]
    public void Options_WithAllPropertiesSet_ValidatesSuccessfully()
    {
        // Arrange
        var options = new SdJwtVerificationOptions
        {
            ClockSkew = TimeSpan.FromMinutes(2),
            RequireKeyBinding = true,
            ExpectedIssuer = "https://issuer.example.com",
            ExpectedAudience = "https://verifier.example.com",
            ExpectedHashAlgorithm = HashAlgorithm.Sha256,
            ExpectedNonce = "test-nonce"
        };

        // Act & Assert
        Assert.Equal(TimeSpan.FromMinutes(2), options.ClockSkew);
        Assert.True(options.RequireKeyBinding);
        Assert.Equal("https://issuer.example.com", options.ExpectedIssuer);
        Assert.Equal("https://verifier.example.com", options.ExpectedAudience);
        Assert.Equal(HashAlgorithm.Sha256, options.ExpectedHashAlgorithm);
        Assert.Equal("test-nonce", options.ExpectedNonce);
        options.Validate();
    }

    [Fact]
    public void Options_WithKeyBindingRequiredAndNonce_ValidatesSuccessfully()
    {
        // Arrange
        var options = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedNonce = "required-nonce"
        };

        // Act & Assert
        Assert.True(options.RequireKeyBinding);
        Assert.Equal("required-nonce", options.ExpectedNonce);
        options.Validate();
    }

    [Fact]
    public void Options_WithIssuerAndAudience_ValidatesSuccessfully()
    {
        // Arrange
        var options = new SdJwtVerificationOptions
        {
            ExpectedIssuer = "https://issuer.example.com",
            ExpectedAudience = "https://audience.example.com"
        };

        // Act & Assert
        Assert.Equal("https://issuer.example.com", options.ExpectedIssuer);
        Assert.Equal("https://audience.example.com", options.ExpectedAudience);
        options.Validate();
    }

    #endregion

    #region Validate Method Tests

    [Fact]
    public void Validate_WithDefaultOptions_DoesNotThrow()
    {
        // Arrange
        var options = new SdJwtVerificationOptions();

        // Act & Assert
        options.Validate(); // Should not throw
    }

    [Fact]
    public void Validate_WithValidCustomOptions_DoesNotThrow()
    {
        // Arrange
        var options = new SdJwtVerificationOptions
        {
            ClockSkew = TimeSpan.FromMinutes(3),
            RequireKeyBinding = true
        };

        // Act & Assert
        options.Validate(); // Should not throw
    }

    [Fact]
    public void Validate_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        var options = new SdJwtVerificationOptions();

        // Act & Assert
        options.Validate();
        options.Validate();
        options.Validate();
    }

    #endregion

    #region Immutability Tests

    [Fact]
    public void Options_IsImmutableAfterConstruction()
    {
        // Arrange
        var options = new SdJwtVerificationOptions
        {
            ClockSkew = TimeSpan.FromMinutes(2),
            RequireKeyBinding = true
        };

        // Act - Verify we cannot modify after construction
        var clockSkew = options.ClockSkew;
        var requireKeyBinding = options.RequireKeyBinding;

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(2), clockSkew);
        Assert.True(requireKeyBinding);
    }

    #endregion

    #region Edge Case Tests

    [Fact]
    public void ExpectedIssuer_WithSpecialCharacters_StoresValue()
    {
        // Arrange
        var issuer = "https://issuer.example.com/path?query=value&other=123";
        var options = new SdJwtVerificationOptions { ExpectedIssuer = issuer };

        // Act & Assert
        Assert.Equal(issuer, options.ExpectedIssuer);
        options.Validate();
    }

    [Fact]
    public void ExpectedAudience_WithUnicode_StoresValue()
    {
        // Arrange
        var audience = "https://例え.jp/audience";
        var options = new SdJwtVerificationOptions { ExpectedAudience = audience };

        // Act & Assert
        Assert.Equal(audience, options.ExpectedAudience);
        options.Validate();
    }

    [Fact]
    public void ExpectedNonce_WithSpecialCharacters_StoresValue()
    {
        // Arrange
        var nonce = "nonce-with-special!@#$%^&*()_+{}[]|:;<>?,./";
        var options = new SdJwtVerificationOptions { ExpectedNonce = nonce };

        // Act & Assert
        Assert.Equal(nonce, options.ExpectedNonce);
        options.Validate();
    }

    [Fact]
    public void ClockSkew_WithExactlyFiveMinutes_ValidatesSuccessfully()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromSeconds(300) };

        // Act & Assert
        Assert.Equal(TimeSpan.FromMinutes(5), options.ClockSkew);
        options.Validate();
    }

    [Fact]
    public void ClockSkew_WithNegativeSeconds_ThrowsOnValidate()
    {
        // Arrange
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromSeconds(-30) };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => options.Validate());
        Assert.Contains("cannot be negative", exception.Message);
    }

    #endregion
}
