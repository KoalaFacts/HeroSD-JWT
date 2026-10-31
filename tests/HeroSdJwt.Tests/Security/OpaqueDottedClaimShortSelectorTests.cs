using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;

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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_NotShortSelect_DottedMemberNestedWithinProfile(bool selectivelyDisclosedParent)
    {
        // The nested object's actual member name is "contact.email", not "email".
        // A dotted member is opaque even when its containing object is nested.
        var child = Base64UrlEncoder.Encode("[\"child-salt\",\"contact.email\",\"private-value\"]");
        var calculator = new DigestCalculator();
        var childDigest = calculator.ComputeDigest(child, HashAlgorithm.Sha256);
        var payload = new Dictionary<string, object> { ["exp"] = 4102444800L };
        string[] disclosures;

        if (selectivelyDisclosedParent)
        {
            var parent = Base64UrlEncoder.Encode(
                $"[\"parent-salt\",\"profile\",{{\"_sd\":[\"{childDigest}\"]}}]");
            payload["_sd"] = new[] { calculator.ComputeDigest(parent, HashAlgorithm.Sha256) };
            disclosures = [parent, child];
        }
        else
        {
            payload["profile"] = new Dictionary<string, object> { ["_sd"] = new[] { childDigest } };
            disclosures = [child];
        }

        var jwt = new JwtSigner().CreateJwt(
            payload, KeyGenerator.Instance.GenerateHmacKey(), SignatureAlgorithm.HS256);
        var credential = new SdJwt(jwt, disclosures, HashAlgorithm.Sha256);
        var presenter = new SdJwtPresenter();

        var exception = Assert.Throws<ArgumentException>(() =>
            presenter.CreatePresentation(credential, ["email"]));
        Assert.Equal("selectedClaimNames", exception.ParamName);

        // Full-path selection remains supported, including its true parent disclosure.
        var selected = presenter.CreatePresentation(credential, ["profile.contact.email"]);
        Assert.Equal(selectivelyDisclosedParent ? 2 : 1, selected.SelectedDisclosures.Count);
    }
}
