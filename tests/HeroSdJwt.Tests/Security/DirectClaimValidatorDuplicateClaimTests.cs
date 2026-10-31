using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Direct IClaimValidator consumers must not accept ambiguous RFC 7519 claim
/// names merely because JsonElement.TryGetProperty returns the last occurrence.
/// Full SD-JWT verification already rejects these duplicate member names.
/// </summary>
public sealed class DirectClaimValidatorDuplicateClaimTests
{
    private static readonly DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    [Theory]
    [InlineData(/*lang=json*/ """{"exp":0,"exp":1900000000}""")]
    [InlineData(/*lang=json*/ """{"\u0065xp":0,"exp":1900000000}""")]
    [InlineData(/*lang=json*/ """{"exp":1900000000,"nbf":1900000100,"nbf":1700000000}""")]
    [InlineData(/*lang=json*/ """{"exp":1900000000,"iat":1900000100,"iat":1700000000}""")]
    public void Should_RejectDuplicateTemporalNames_WhenValidatingDirectly(string json)
    {
        using var document = JsonDocument.Parse(json);

        Assert.False(new ClaimValidator().ValidateTemporalClaims(
            document.RootElement,
            new SdJwtVerificationOptions { ClockSkew = TimeSpan.Zero },
            _now));
    }

    [Theory]
    [InlineData(/*lang=json*/ """{"iss":"untrusted","iss":"trusted"}""")]
    [InlineData(/*lang=json*/ """{"\u0069ss":"untrusted","iss":"trusted"}""")]
    public void Should_RejectDuplicateIssuerNames_WhenValidatingDirectly(string json)
    {
        using var document = JsonDocument.Parse(json);

        Assert.False(new ClaimValidator().ValidateIssuer(document.RootElement, "trusted"));
    }

    [Theory]
    [InlineData(/*lang=json*/ """{"aud":"untrusted","aud":"trusted"}""")]
    [InlineData(/*lang=json*/ """{"\u0061ud":"untrusted","aud":"trusted"}""")]
    public void Should_RejectDuplicateAudienceNames_WhenValidatingDirectly(string json)
    {
        using var document = JsonDocument.Parse(json);

        Assert.False(new ClaimValidator().ValidateAudience(document.RootElement, "trusted"));
    }

    [Fact]
    public void Should_KeepUniqueRegisteredClaimsValid_WhenValidatingDirectly()
    {
        using var document = JsonDocument.Parse(
            """{"exp":1900000000,"iss":"trusted","aud":["other","trusted"]}""");
        var validator = new ClaimValidator();

        Assert.True(validator.ValidateTemporalClaims(
            document.RootElement,
            new SdJwtVerificationOptions { ClockSkew = TimeSpan.Zero },
            _now));
        Assert.True(validator.ValidateIssuer(document.RootElement, "trusted"));
        Assert.True(validator.ValidateAudience(document.RootElement, "trusted"));
    }
}
