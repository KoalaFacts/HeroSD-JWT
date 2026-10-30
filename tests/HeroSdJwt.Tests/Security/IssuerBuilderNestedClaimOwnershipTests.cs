using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Presentation;
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

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Should_SnapshotMutablePocoClaims_When_Configured(bool useWithClaims, bool selectNestedEmail)
    {
        var profile = new MutableProfile
        {
            Name = "Alice",
            Contact = new MutableContact { Email = "original@example.test" }
        };

        var builder = SdJwtIssuerBuilder.Create();
        if (useWithClaims)
        {
            builder.WithClaims(new Dictionary<string, object>
            {
                ["sub"] = "holder-1",
                ["profile"] = profile
            });
        }
        else
        {
            builder.WithClaim("sub", "holder-1")
                .WithClaim("profile", profile);
        }

        if (selectNestedEmail)
        {
            builder.MakeSelective("profile.Contact.Email");
        }

        builder.SignWithHmac(_issuerKey);

        // Mutating a caller-owned object after configuration must not change
        // the signed payload or the selectively disclosed value.
        profile.Name = "Mallory";
        profile.Contact.Email = "modified@example.test";

        var sdJwt = builder.Build();
        if (selectNestedEmail)
        {
            var parser = new DisclosureParser();
            var emailDisclosure = Assert.Single(sdJwt.Disclosures,
                disclosure => parser.GetClaimName(disclosure) == "Email");
            Assert.Equal("original@example.test", parser.Parse(emailDisclosure).ClaimValue.GetString());
        }
        else
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(sdJwt.Jwt.Split('.')[1]));
            var signedProfile = payload.RootElement.GetProperty("profile");
            Assert.Equal("Alice", signedProfile.GetProperty("Name").GetString());
            Assert.Equal("original@example.test", signedProfile.GetProperty("Contact").GetProperty("Email").GetString());
        }
    }

    [Fact]
    public void Should_PreserveEnumerableValueTypeSnapshot_When_NestedValueMutates()
    {
        // ImmutableArray is a value-type IEnumerable, but its elements can be
        // mutable objects. It was snapshotted before the POCO fix and must
        // continue to be snapshotted at configuration time.
        var contact = new MutableContact { Email = "original@example.test" };
        var contacts = System.Collections.Immutable.ImmutableArray.Create(contact);
        var builder = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "holder-1")
            .WithClaim("contacts", contacts)
            .SignWithHmac(_issuerKey);

        contact.Email = "modified@example.test";

        var sdJwt = builder.Build();
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(sdJwt.Jwt.Split('.')[1]));
        Assert.Equal(
            "original@example.test",
            payload.RootElement.GetProperty("contacts")[0].GetProperty("Email").GetString());
    }

    private sealed class MutableProfile
    {
        public string Name { get; set; } = string.Empty;

        public MutableContact Contact { get; set; } = new();
    }

    private sealed class MutableContact
    {
        public string Email { get; set; } = string.Empty;
    }
}
