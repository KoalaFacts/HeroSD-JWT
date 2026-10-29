using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

public class IssuerBuilderNestedClaimOwnershipTests
{
    private static readonly byte[] _issuerKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public void Should_RetainNestedDictionaryAndList_When_WithClaimsSourceIsMutated()
    {
        var roles = new List<string> { "reader" };
        var profile = new Dictionary<string, object>
        {
            ["name"] = "Alice",
            ["roles"] = roles
        };
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "holder-1",
            ["profile"] = profile
        };

        var builder = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .SignWithHmac(_issuerKey);

        profile["name"] = "Mallory";
        roles[0] = "admin";

        var sdJwt = builder.Build();
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(sdJwt.Jwt.Split('.')[1]));
        var signedProfile = payload.RootElement.GetProperty("profile");

        Assert.Equal("Alice", signedProfile.GetProperty("name").GetString());
        Assert.Equal("reader", signedProfile.GetProperty("roles")[0].GetString());
    }

    [Fact]
    public void Should_RetainArrayAndNestedDictionary_When_WithClaimSourceIsMutated()
    {
        var firstDevice = new Dictionary<string, object> { ["enabled"] = true };
        object[] devices = [firstDevice, "original"];

        var builder = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "holder-1")
            .WithClaim("devices", devices)
            .SignWithHmac(_issuerKey);

        firstDevice["enabled"] = false;
        devices[1] = "changed";

        var sdJwt = builder.Build();
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(sdJwt.Jwt.Split('.')[1]));
        var signedDevices = payload.RootElement.GetProperty("devices");

        Assert.True(signedDevices[0].GetProperty("enabled").GetBoolean());
        Assert.Equal("original", signedDevices[1].GetString());
    }

    [Fact]
    public void Should_RetainNestedJsonElement_When_SourceDocumentIsDisposedBeforeBuild()
    {
        SdJwtIssuerBuilder builder;
        using (var document = JsonDocument.Parse("\"private@example.com\""))
        {
            var profile = new Dictionary<string, object>
            {
                ["email"] = document.RootElement,
                ["city"] = "Sydney"
            };

            builder = SdJwtIssuerBuilder.Create()
                .WithClaim("sub", "holder-1")
                .WithClaim("profile", profile)
                .MakeSelective("profile.email")
                .SignWithHmac(_issuerKey);
        }

        var sdJwt = builder.Build();
        using var disclosure = JsonDocument.Parse(Base64UrlEncoder.DecodeString(Assert.Single(sdJwt.Disclosures)));
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(sdJwt.Jwt.Split('.')[1]));

        Assert.Equal("email", disclosure.RootElement[1].GetString());
        Assert.Equal("private@example.com", disclosure.RootElement[2].GetString());
        Assert.Equal("Sydney", payload.RootElement.GetProperty("profile").GetProperty("city").GetString());
    }
}
