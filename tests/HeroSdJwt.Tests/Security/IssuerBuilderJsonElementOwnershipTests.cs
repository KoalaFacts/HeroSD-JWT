using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

public class IssuerBuilderJsonElementOwnershipTests
{
    private static readonly byte[] _issuerKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public void Should_KeepSelectiveJsonElement_When_WithClaimSourceDocumentIsDisposed()
    {
        SdJwtIssuerBuilder builder;
        using (var document = JsonDocument.Parse("\"private@example.com\""))
        {
            builder = SdJwtIssuerBuilder.Create()
                .WithClaim("sub", "holder-1")
                .WithClaim("email", document.RootElement)
                .MakeSelective("email")
                .SignWithHmac(_issuerKey);
        }

        var sdJwt = builder.Build();
        using var disclosure = JsonDocument.Parse(Base64UrlEncoder.DecodeString(Assert.Single(sdJwt.Disclosures)));

        Assert.Equal("email", disclosure.RootElement[1].GetString());
        Assert.Equal("private@example.com", disclosure.RootElement[2].GetString());
    }

    [Fact]
    public void Should_KeepNestedJsonElement_When_WithClaimsSourceDocumentIsDisposed()
    {
        SdJwtIssuerBuilder builder;
        using (var document = JsonDocument.Parse("""{"city":"Sydney","email":"private@example.com"}"""))
        {
            builder = SdJwtIssuerBuilder.Create()
                .WithClaims(new Dictionary<string, object>
                {
                    ["sub"] = "holder-1",
                    ["profile"] = document.RootElement
                })
                .MakeSelective("profile.email")
                .SignWithHmac(_issuerKey);
        }

        var sdJwt = builder.Build();
        using var disclosure = JsonDocument.Parse(Base64UrlEncoder.DecodeString(Assert.Single(sdJwt.Disclosures)));
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(sdJwt.Jwt.Split('.')[1]));

        Assert.Equal("email", disclosure.RootElement[1].GetString());
        Assert.Equal("private@example.com", disclosure.RootElement[2].GetString());
        Assert.Equal("Sydney", payload.RootElement.GetProperty("profile").GetProperty("city").GetString());
        Assert.False(payload.RootElement.GetProperty("profile").TryGetProperty("email", out _));
    }
}
