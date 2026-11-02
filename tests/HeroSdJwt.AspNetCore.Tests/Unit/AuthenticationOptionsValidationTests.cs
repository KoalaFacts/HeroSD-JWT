using HeroSdJwt.AspNetCore.Authentication;

namespace HeroSdJwt.AspNetCore.Tests.Unit;

public sealed class AuthenticationOptionsValidationTests
{
    [Fact]
    public void Should_RejectMissingVerificationPolicyBeforeAuthentication()
    {
        var options = new SdJwtAuthenticationOptions
        {
            FallbackKey = new byte[32],
            VerificationOptions = null!
        };

        var exception = Assert.Throws<InvalidOperationException>(options.Validate);

        Assert.Contains(nameof(SdJwtAuthenticationOptions.VerificationOptions), exception.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("Bearer Other")]
    [InlineData("Bearer\t")]
    [InlineData("Bearer\"")]
    [InlineData("Bearer\r\nInjected")]
    [InlineData("Bearer\u0085")]
    public void Should_RejectInvalidHttpAuthenticationSchemes(string tokenScheme)
    {
        var options = new SdJwtAuthenticationOptions
        {
            FallbackKey = new byte[32],
            TokenScheme = tokenScheme
        };

        var exception = Assert.Throws<InvalidOperationException>(options.Validate);

        Assert.Contains(nameof(SdJwtAuthenticationOptions.TokenScheme), exception.Message);
    }

    [Theory]
    [InlineData("Bearer")]
    [InlineData("DPoP")]
    [InlineData("SD-JWT")]
    [InlineData("Custom+Token")]
    public void Should_AcceptValidHttpAuthenticationSchemes(string tokenScheme)
    {
        var options = new SdJwtAuthenticationOptions
        {
            FallbackKey = new byte[32],
            TokenScheme = tokenScheme
        };

        options.Validate();
    }
}
