using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Presentation;

namespace HeroSdJwt.Tests.Unit.Presentation;

/// <summary>
/// Duplicate claim-value names can be interpreted differently by JSON consumers,
/// even when the enclosing disclosure digest is valid.
/// </summary>
public class DisclosureDuplicateMemberTests
{
    [Theory]
    [InlineData(/*lang=json,strict*/ """["salt","profile",{"role":"user","role":"admin"}]""")]
    [InlineData(/*lang=json,strict*/ """["salt","profile",{"role":"user","\u0072ole":"admin"}]""")]
    [InlineData(/*lang=json,strict*/ """["salt","profile",{"address":{"zip":"1","zip":"2"}}]""")]
    [InlineData(/*lang=json,strict*/ """["salt","profile",[{"role":"user","role":"admin"}]]""")]
    [InlineData(/*lang=json,strict*/ """["salt",{"role":"user","role":"admin"}]""")]
    public void Should_RejectDuplicateObjectNamesInsideDisclosedValues(string json)
    {
        var disclosure = Base64UrlEncoder.Encode(json);
        var parser = new DisclosureParser();

        _ = Assert.Throws<MalformedDisclosureException>(() => parser.Parse(disclosure));
    }

    [Fact]
    public void Should_AllowMatchingNamesInDifferentNestedObjects()
    {
        const string json = /*lang=json,strict*/ """["salt","profile",{"primary":{"role":"admin"},"secondary":{"role":"user"}}]""";
        var parser = new DisclosureParser();

        var disclosure = parser.Parse(Base64UrlEncoder.Encode(json));

        Assert.Equal("admin", disclosure.ClaimValue.GetProperty("primary").GetProperty("role").GetString());
        Assert.Equal("user", disclosure.ClaimValue.GetProperty("secondary").GetProperty("role").GetString());
    }
}
