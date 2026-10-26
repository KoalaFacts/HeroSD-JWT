using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A caller must not supply SD-JWT digest references for the issuer to sign.
/// Otherwise an attacker controlling claim data could choose a Disclosure digest
/// and later present a claim that the issuer never deliberately disclosed.
/// </summary>
public class IssuerReservedDisclosureMembersTests
{
    private static readonly byte[] SigningKey = new byte[32];

    [Fact]
    public void Should_RejectCallerProvidedTopLevelSdDigest()
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-1",
            ["_sd"] = new[] { CreateForgedDigest() }
        };

        AssertRejected(claims, "_sd");
    }

    [Fact]
    public void Should_RejectCallerProvidedNestedSdDigest()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new Dictionary<string, object>
            {
                ["display"] = "Alice",
                ["_sd"] = new[] { CreateForgedDigest() }
            }
        };

        AssertRejected(claims, "_sd");
    }

    [Fact]
    public void Should_RejectCallerProvidedSdDigestInAnonymousObject()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { display = "Alice", _sd = new[] { CreateForgedDigest() } }
        };

        AssertRejected(claims, "_sd");
    }

    [Fact]
    public void Should_RejectCallerProvidedSdDigestInJsonElement()
    {
        using var document = JsonDocument.Parse(\"{\\\"profile\\\":{\\\"_sd\\\":[]}}\");
        var claims = new Dictionary<string, object>
        {
            ["payload"] = document.RootElement.Clone()
        };

        AssertRejected(claims, "_sd");
    }

    [Fact]
    public void Should_RejectCallerProvidedArrayDisclosurePlaceholder()
    {
        var claims = new Dictionary<string, object>
        {
            ["roles"] = new object[]
            {
                new Dictionary<string, string> { ["..."] = CreateForgedDigest() }
            }
        };

        AssertRejected(claims, "...");
    }

    [Fact]
    public void Should_RejectCallerProvidedPlaceholderInNestedJsonArray()
    {
        using var document = JsonDocument.Parse(\"{\\\"items\\\":[{\\\"...\\\":\\\"injected\\\"}]}\");
        var claims = new Dictionary<string, object>
        {
            ["payload"] = document.RootElement.Clone()
        };

        AssertRejected(claims, "...");
    }

    [Fact]
    public void Should_RejectCallerProvidedTopLevelPlaceholderName()
    {
        var claims = new Dictionary<string, object>
        {
            ["..."] = "user-data"
        };

        AssertRejected(claims, "...");
    }

    [Fact]
    public void Should_KeepIssuerGeneratedNestedAndArrayDisclosureReferences()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { display = "Alice", city = "Sydney" },
            ["roles"] = new[] { "viewer", "editor" }
        };

        var sdJwt = TestHelpers.CreateIssuer().CreateSdJwt(
            claims, ["profile.city", "roles[0]"], SigningKey, HashAlgorithm.Sha256);

        Assert.Equal(2, sdJwt.Disclosures.Count);

        var parts = sdJwt.Jwt.Split('.');
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(parts[1]));
        Assert.Equal(JsonValueKind.Array, payload.RootElement.GetProperty("profile").GetProperty("_sd").ValueKind);
        Assert.Equal(JsonValueKind.String, payload.RootElement.GetProperty("roles")[0].GetProperty("...").ValueKind);
    }

    private static void AssertRejected(Dictionary<string, object> claims, string reservedName)
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(claims, [], SigningKey, HashAlgorithm.Sha256));

        Assert.Contains(reservedName, exception.Message);
    }

    private static string CreateForgedDigest()
    {
        using var document = JsonDocument.Parse("true");
        var disclosure = new DisclosureGenerator().GenerateDisclosure("admin", document.RootElement);
        return new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
    }
}
