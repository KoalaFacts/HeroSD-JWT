using HeroSdJwt.Issuance;
using HeroSdJwt.Presentation;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Both disclosure shapes must retain fresh canonical 128-bit salts when the
/// generator encodes its temporary random bytes without allocating an array.
/// </summary>
public class DisclosureSaltEncodingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_ProduceFreshCanonical128BitSalts_ForBothDisclosureShapes(bool arrayElement)
    {
        var generator = new DisclosureGenerator();
        var parser = new DisclosureParser();
        using var document = JsonDocument.Parse("\"value\"");
        var salts = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < 256; i++)
        {
            var encoded = arrayElement
                ? generator.GenerateArrayElementDisclosure(document.RootElement)
                : generator.GenerateDisclosure("name", document.RootElement);

            var disclosure = parser.Parse(encoded);
            Assert.Equal(arrayElement, disclosure.IsArrayElement);
            Assert.Equal("value", disclosure.ClaimValue.GetString());
            Assert.Matches("^[A-Za-z0-9_-]{22}$", disclosure.Salt);
            var rawSalt = Convert.FromBase64String(
                disclosure.Salt.Replace('-', '+').Replace('_', '/') + "==");
            Assert.Equal(16, rawSalt.Length);
            Assert.True(salts.Add(disclosure.Salt), "Every disclosure must use a fresh salt.");
        }
    }
}
