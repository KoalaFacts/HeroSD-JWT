using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Presentation;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Malformed JSON must remain a disclosure-domain error at the standalone parser boundary.
/// </summary>
public sealed class DisclosureParserMalformedJsonBoundaryTests
{
    [Theory]
    [InlineData("")]
    [InlineData("[")]
    [InlineData("[\"salt\",\"claim\",]")]
    [InlineData("[\"salt\",")]
    public void Parse_MalformedJson_ThrowsMalformedDisclosureWithCause(string json)
    {
        var encoded = Base64UrlEncoder.Encode(json);

        var exception = Assert.Throws<MalformedDisclosureException>(
            () => new DisclosureParser().Parse(encoded));

        Assert.IsAssignableFrom<JsonException>(exception.InnerException);
    }

    [Fact]
    public void GetClaimName_MalformedJson_ThrowsMalformedDisclosure()
    {
        var encoded = Base64UrlEncoder.Encode("[\"salt\",\"claim\"");

        var exception = Assert.Throws<MalformedDisclosureException>(
            () => new DisclosureParser().GetClaimName(encoded));

        Assert.IsAssignableFrom<JsonException>(exception.InnerException);
    }
    [Theory]
    [InlineData("!")]
    [InlineData("abc=")]
    [InlineData("ab cd")]
    public void Parse_MalformedBase64Url_ThrowsMalformedDisclosureWithCause(string encoded)
    {
        var exception = Assert.Throws<MalformedDisclosureException>(
            () => new DisclosureParser().Parse(encoded));

        Assert.IsAssignableFrom<SdJwtException>(exception.InnerException);
    }

    [Fact]
    public void GetClaimName_InvalidUtf8Disclosure_ThrowsMalformedDisclosureWithCause()
    {
        var encoded = Base64UrlEncoder.Encode(new byte[] { 0xFF });

        var exception = Assert.Throws<MalformedDisclosureException>(
            () => new DisclosureParser().GetClaimName(encoded));

        Assert.IsAssignableFrom<SdJwtException>(exception.InnerException);
    }
}
