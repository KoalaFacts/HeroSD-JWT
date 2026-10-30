using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using System.Text.Json;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// RFC 7519 permits opaque top-level claim names containing dots or
/// brackets, without requiring them to be absolute URIs.
/// </summary>
public class OpaqueTopLevelClaimDisclosureTests
{
    [Theory]
    [InlineData("account.tier", false)]
    [InlineData("account.tier", true)]
    [InlineData("employee[status]", false)]
    [InlineData("employee[status]", true)]
    [InlineData("permissions[0]", false)]
    [InlineData("permissions[0]", true)]
    public void Should_RoundTripOpaqueTopLevelName_WhenNoStructuralBaseExists(
        string claimName, bool importedWithoutCachedMapping)
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var issued = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "holder-1")
            .WithClaim(claimName, "private-value")
            .MakeSelective(claimName)
            .SignWithHmac(key)
            .Build();

        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(issued.Jwt.Split('.')[1]));
        Assert.False(payload.RootElement.TryGetProperty(claimName, out _));
        Assert.True(payload.RootElement.TryGetProperty("_sd", out _));

        var credential = importedWithoutCachedMapping
            ? new SdJwt(issued.Jwt, issued.Disclosures, issued.HashAlgorithm)
            : issued;
        var presenter = new SdJwtPresenter();
        var selection = presenter.CreatePresentation(credential, [claimName]);
        _ = Assert.Single(selection.SelectedDisclosures);

        var result = TestHelpers.CreateVerifier().VerifyPresentation(
            presenter.FormatPresentation(selection), key);
        Assert.True(result.IsValid);
        Assert.Equal("private-value", result.DisclosedClaims[claimName].GetString());
    }

    [Theory]
    [InlineData("profile.email")]
    [InlineData("roles[1]")]
    public void Should_RejectAmbiguousSelector_WhenLiteralAndStructuralClaimsCoexist(string selector)
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var issuer = SdJwtIssuerBuilder.Create()
            .WithClaim("profile", new { email = "nested-secret" })
            .WithClaim("roles", new[] { "viewer", "nested-secret" })
            .WithClaim(selector, "literal-secret")
            .MakeSelective(selector)
            .SignWithHmac(key);

        var exception = Assert.Throws<ArgumentException>(issuer.Build);
        Assert.Equal("selectivelyDisclosableClaims", exception.ParamName);
    }
}
