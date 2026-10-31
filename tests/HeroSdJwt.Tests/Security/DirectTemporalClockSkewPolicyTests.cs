using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

public sealed class DirectTemporalClockSkewPolicyTests
{
    private static readonly DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    [Fact]
    public void Should_RejectExpiredToken_WhenDirectCallUsesExcessiveClockSkew()
    {
        // A direct IClaimValidator caller does not pass through the verifier's options.Validate().
        // An hour of skew must not make a token expired ten minutes ago valid.
        using var document = JsonDocument.Parse("""{"exp":1799999400}""");
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromHours(1) };

        Assert.False(new ClaimValidator().ValidateTemporalClaims(document.RootElement, options, _now));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(301)]
    public void Should_FailClosedForOutOfPolicyClockSkew_WhenCallingValidatorDirectly(int skewSeconds)
    {
        using var document = JsonDocument.Parse("""{"exp":1800003600}""");
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromSeconds(skewSeconds) };

        Assert.False(new ClaimValidator().ValidateTemporalClaims(document.RootElement, options, _now));
    }

    [Fact]
    public void Should_PreserveAllowedFiveMinuteClockSkew()
    {
        using var document = JsonDocument.Parse("""{"exp":1799999880}""");
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromMinutes(5) };

        Assert.True(new ClaimValidator().ValidateTemporalClaims(document.RootElement, options, _now));
    }
}
