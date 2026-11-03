using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Registered issuer strings must decode without malformed UTF-16 even when
/// the relying party has not configured an issuer matching policy.
/// </summary>
public sealed class IssuerUnicodeValidationTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("https://issuer.example")]
    public void Should_RejectMalformedEscapedIssuer_RegardlessOfIssuerPolicy(string? expectedIssuer)
    {
        // The JSON parser accepts a lone escaped surrogate as a string token,
        // but it is not a valid decoded StringOrURI registered issuer.
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"iss":"\uD800"}""");

        Assert.False(new ClaimValidator().ValidateIssuer(document.RootElement, expectedIssuer));
    }

    [Fact]
    public void Should_AcceptValidEscapedIssuer_WhenDecodedValueMatches()
    {
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"iss":"https://issu\u0065r.example"}""");

        Assert.True(new ClaimValidator().ValidateIssuer(
            document.RootElement, "https://issuer.example"));
    }
}
