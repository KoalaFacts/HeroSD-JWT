using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Disclosure metadata must not change when converted to signed UTF-8 JSON.
/// Unpaired UTF-16 surrogates cannot be round-tripped without replacement.
/// </summary>
public class DisclosureMetadataUnicodeAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Should_RejectUnpairedSurrogatesInDisclosureSalt(int caseId)
    {
        var malformed = InvalidMetadata(caseId);
        using var document = JsonDocument.Parse("\"value\"");

        Assert.Throws<ArgumentException>(() =>
            new Disclosure(malformed, "name", document.RootElement));
        Assert.Throws<ArgumentException>(() =>
            new Disclosure(malformed, document.RootElement));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Should_RejectUnpairedSurrogatesInObjectClaimName(int caseId)
    {
        var malformed = InvalidMetadata(caseId);
        using var document = JsonDocument.Parse("\"value\"");

        Assert.Throws<ArgumentException>(() =>
            new Disclosure("salt", malformed, document.RootElement));
        Assert.Throws<ArgumentException>(() =>
            new DisclosureGenerator().GenerateDisclosure(malformed, document.RootElement));
    }

    [Fact]
    public void Should_PreserveValidSupplementaryUnicodeInDisclosureMetadata()
    {
        using var document = JsonDocument.Parse("\"value\"");
        var parser = new DisclosureParser();

        var objectDisclosure = new Disclosure("salt😀", "name😀", document.RootElement);
        var parsed = parser.Parse(Base64UrlEncoder.Encode(objectDisclosure.ToJson()));
        Assert.Equal("salt😀", parsed.Salt);
        Assert.Equal("name😀", parsed.ClaimName);

        var arrayDisclosure = new Disclosure("salt😀", document.RootElement);
        Assert.Equal("salt😀", parser.Parse(Base64UrlEncoder.Encode(arrayDisclosure.ToJson())).Salt);

        var generated = new DisclosureGenerator().GenerateDisclosure("name😀", document.RootElement);
        Assert.Equal("name😀", parser.Parse(generated).ClaimName);
    }

    private static string InvalidMetadata(int caseId) => caseId switch
    {
        0 => "\uD800",
        1 => "\uDC00",
        2 => "before\uD800after",
        3 => "before\uDC00after",
        _ => throw new ArgumentOutOfRangeException(nameof(caseId))
    };
}
