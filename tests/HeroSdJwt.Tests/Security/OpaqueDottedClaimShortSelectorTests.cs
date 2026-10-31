using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A literal top-level dotted member is not a nested claim path. The short-name
/// convenience must never disclose it when the holder asks for a nested leaf.
/// </summary>
public class OpaqueDottedClaimShortSelectorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RequireExactSelector_ForOpaqueDottedTopLevelClaim(bool importWithoutCachedMapping)
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var issued = SdJwtIssuerBuilder.Create()
            .WithClaim("contact.email", "private-value")
            .MakeSelective("contact.email")
            .SignWithHmac(key)
            .Build();

        var credential = importWithoutCachedMapping
            ? new SdJwt(issued.Jwt, issued.Disclosures, issued.HashAlgorithm)
            : issued;
        var presenter = new SdJwtPresenter();

        var exception = Assert.Throws<ArgumentException>(() =>
            presenter.CreatePresentation(credential, ["email"]));
        Assert.Equal("selectedClaimNames", exception.ParamName);

        // The full literal name must remain selectable.
        _ = Assert.Single(presenter.CreatePresentation(credential, ["contact.email"]).SelectedDisclosures);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_DiscloseOnlyRealNestedLeaf_WhenOpaqueDottedClaimSharesItsSuffix(bool importWithoutCachedMapping)
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var issued = SdJwtIssuerBuilder.Create()
            .WithClaim("profile", new { email = "nested-value" })
            .WithClaim("contact.email", "opaque-private-value")
            .MakeSelective("profile.email", "contact.email")
            .SignWithHmac(key)
            .Build();

        var credential = importWithoutCachedMapping
            ? new SdJwt(issued.Jwt, issued.Disclosures, issued.HashAlgorithm)
            : issued;
        var presenter = new SdJwtPresenter();

        var presentation = presenter.CreatePresentation(credential, ["email"]);
        _ = Assert.Single(presentation.SelectedDisclosures);
        var verified = TestHelpers.CreateVerifier().VerifyPresentation(
            presenter.FormatPresentation(presentation), key);
        Assert.True(verified.IsValid);
        Assert.DoesNotContain("contact.email", verified.DisclosedClaims.Keys);
    }
}
