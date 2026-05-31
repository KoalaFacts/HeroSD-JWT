using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Validation tests for <see cref="SdJwtVerificationOptions"/> focused on the key-binding
/// preconditions. When key binding is required, both an expected audience and an expected
/// nonce must be configured to prevent token replay across audiences/sessions.
/// </summary>
public class SdJwtVerificationOptionsKeyBindingTests
{
    [Fact]
    public void Validate_RequireKeyBinding_WithoutAudience_Throws()
    {
        var options = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedNonce = "nonce-123"
        };

        var ex = Assert.Throws<ArgumentException>(options.Validate);
        Assert.Equal("ExpectedAudiences", ex.ParamName);
    }

    [Fact]
    public void Validate_RequireKeyBinding_WithAudienceButNoNonce_Throws()
    {
        var options = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = "https://verifier.example.com"
        };

        var ex = Assert.Throws<ArgumentException>(options.Validate);
        Assert.Equal("ExpectedNonce", ex.ParamName);
    }

    [Fact]
    public void Validate_RequireKeyBinding_WithAudienceAndNonce_DoesNotThrow()
    {
        var options = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = "https://verifier.example.com",
            ExpectedNonce = "nonce-123"
        };

        Assert.Null(Record.Exception(options.Validate));
    }

    [Fact]
    public void Validate_RequireKeyBinding_WithExpectedAudiencesList_DoesNotThrow()
    {
        var options = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudiences = ["https://verifier.example.com"],
            ExpectedNonce = "nonce-123"
        };

        Assert.Null(Record.Exception(options.Validate));
    }

    [Fact]
    public void Validate_WithNegativeClockSkew_Throws()
    {
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromSeconds(-1) };

        var ex = Assert.Throws<ArgumentException>(options.Validate);
        Assert.Equal("ClockSkew", ex.ParamName);
    }

    [Fact]
    public void Validate_WithExcessiveClockSkew_Throws()
    {
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(6) };

        var ex = Assert.Throws<ArgumentException>(options.Validate);
        Assert.Equal("ClockSkew", ex.ParamName);
    }

    [Fact]
    public void Validate_WithoutKeyBinding_AndNoAudience_DoesNotThrow()
    {
        var options = new SdJwtVerificationOptions { RequireKeyBinding = false };

        Assert.Null(Record.Exception(options.Validate));
    }
}
