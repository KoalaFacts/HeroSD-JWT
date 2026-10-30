using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using System.Text.Json;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// RFC 7519 permits URI-valued claim names. An exact top-level claim name
/// must remain selectable even when its spelling contains path separators.
/// </summary>
public class LiteralUriClaimDisclosureTests
{
    [Theory]
    [InlineData("https://example.org/claims/employee-id")]
    [InlineData("https://example.org/credentials/contact.email")]
    [InlineData("urn:example:claims.employee-id")]
    [InlineData("urn:example:employee.contact.email")]
    public void Should_RoundTripSelectedUriClaim_WhenNameContainsPathSeparators(string claimName)
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var credential = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "holder-1")
            .WithClaim(claimName, "private-value")
            .MakeSelective(claimName)
            .SignWithHmac(key)
            .Build();

        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(credential.Jwt.Split('.')[1]));
        Assert.False(payload.RootElement.TryGetProperty(claimName, out _));
        Assert.True(payload.RootElement.TryGetProperty("_sd", out _));

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentation(credential, [claimName]);
        _ = Assert.Single(presentation.SelectedDisclosures);

        var result = TestHelpers.CreateVerifier().VerifyPresentation(
            presenter.FormatPresentation(presentation), key);
        Assert.True(result.IsValid);
        Assert.Equal("private-value", result.DisclosedClaims[claimName].GetString());
    }

    [Theory]
    [InlineData("https://example.org/credentials/contact.email", "email", false)]
    [InlineData("https://example.org/credentials/contact.email", "contact.email", true)]
    [InlineData("urn:example:employee.contact.email", "email", false)]
    [InlineData("urn:example:employee.contact.email", "contact.email", true)]
    public void Should_RequireExactUriName_InsteadOfDisclosingByShortSuffix(
        string claimName,
        string shortName,
        bool importWithoutCachedMapping)
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var issued = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "holder-1")
            .WithClaim(claimName, "private-value")
            .MakeSelective(claimName)
            .SignWithHmac(key)
            .Build();

        // The rule applies both to issuer-cached maps and imported SD-JWTs.
        var credential = importWithoutCachedMapping
            ? new SdJwt(issued.Jwt, issued.Disclosures, issued.HashAlgorithm)
            : issued;
        var presenter = new SdJwtPresenter();

        var exception = Assert.Throws<ArgumentException>(() =>
            presenter.CreatePresentation(credential, [shortName]));
        Assert.Equal("selectedClaimNames", exception.ParamName);

        // An exact URI selection must continue to disclose the claim.
        _ = Assert.Single(presenter.CreatePresentation(credential, [claimName]).SelectedDisclosures);
    }

    [Fact]
    public void Should_RejectUnknownUriSelector_WhenClaimDoesNotExist()
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var exception = Assert.Throws<ArgumentException>(() => SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "holder-1")
            .MakeSelective("https://example.org/claims/missing")
            .SignWithHmac(key)
            .Build());

        Assert.Contains("does not exist", exception.Message);
    }
}
