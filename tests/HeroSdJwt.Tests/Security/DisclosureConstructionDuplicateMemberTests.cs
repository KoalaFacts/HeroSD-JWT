using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A directly created Disclosure must not contain JSON member names that
/// the public DisclosureParser and the verifier must reject.
/// </summary>
public sealed class DisclosureConstructionDuplicateMemberTests
{
    [Theory]
    [InlineData(/*lang=json,strict*/ """{"role":"reader","role":"admin"}""")]
    [InlineData(/*lang=json,strict*/ """{"role":"reader","\u0072ole":"admin"}""")]
    [InlineData(/*lang=json,strict*/ """{"profile":[{"role":"reader","role":"admin"}]}""")]
    public void Should_RejectDuplicateJsonMembersInDirectDisclosureConstructors(string json)
    {
        using var document = JsonDocument.Parse(json);
        var value = document.RootElement;

        _ = Assert.Throws<ArgumentException>(() => new Disclosure("salt", "profile", value));
        _ = Assert.Throws<ArgumentException>(() => new Disclosure("salt", value));
    }

    [Theory]
    [InlineData(/*lang=json,strict*/ """{"role":"reader","role":"admin"}""")]
    [InlineData(/*lang=json,strict*/ """{"role":"reader","\u0072ole":"admin"}""")]
    [InlineData(/*lang=json,strict*/ """{"profile":[{"role":"reader","role":"admin"}]}""")]
    public void Should_RejectDuplicateJsonMembersInGeneratedDisclosures(string json)
    {
        using var document = JsonDocument.Parse(json);
        var generator = new DisclosureGenerator();

        _ = Assert.Throws<ArgumentException>(() => generator.GenerateDisclosure("profile", document.RootElement));
        _ = Assert.Throws<ArgumentException>(() => generator.GenerateArrayElementDisclosure(document.RootElement));
    }

    [Fact]
    public void Should_AcceptSameMemberNameInDistinctNestedObjects()
    {
        using var document = JsonDocument.Parse(
            /*lang=json,strict*/ """{"primary":{"role":"reader"},"secondary":{"role":"admin"}}""");
        var generator = new DisclosureGenerator();
        var parser = new DisclosureParser();

        var objectDisclosure = generator.GenerateDisclosure("profile", document.RootElement);
        var arrayDisclosure = generator.GenerateArrayElementDisclosure(document.RootElement);

        Assert.Equal("profile", parser.Parse(objectDisclosure).ClaimName);
        Assert.True(parser.Parse(arrayDisclosure).IsArrayElement);
    }
}
