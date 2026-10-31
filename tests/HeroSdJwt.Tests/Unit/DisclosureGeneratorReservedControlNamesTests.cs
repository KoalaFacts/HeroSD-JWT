using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// A public disclosure factory must not emit protocol control names that
/// the verifier and disclosure parser will reject under RFC 9901.
/// </summary>
public class DisclosureGeneratorReservedControlNamesTests
{
    [Theory]
    [InlineData("_sd")]
    [InlineData("_sd_alg")]
    [InlineData("...")]
    public void Should_RejectProtocolControlNames_WhenGeneratingObjectDisclosure(string claimName)
    {
        using var document = JsonDocument.Parse("\"value\"");
        var generator = new DisclosureGenerator();

        Assert.Throws<ArgumentException>(() =>
            generator.GenerateDisclosure(claimName, document.RootElement));

        // The public model constructor is another route to the same
        // malformed disclosure, without going through the generator.
        Assert.Throws<ArgumentException>(() =>
        {
            _ = new Disclosure("salt", claimName, document.RootElement);
        });
    }

    [Theory]
    [InlineData("_sd_extra")]
    [InlineData("_sd_algorithm")]
    [InlineData("...suffix")]
    public void Should_KeepOrdinaryLookalikeNames_WhenGeneratingObjectDisclosure(string claimName)
    {
        using var document = JsonDocument.Parse("\"value\"");
        var generator = new DisclosureGenerator();
        var encoded = generator.GenerateDisclosure(claimName, document.RootElement);

        var parsed = new DisclosureParser().Parse(encoded);
        Assert.Equal(claimName, parsed.ClaimName);
        Assert.Equal("value", parsed.ClaimValue.GetString());
    }
}
