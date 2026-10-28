using HeroSdJwt.Issuance;
using HeroSdJwt.Presentation;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Ensures a requested nested selective-disclosure path is actually present
/// and traversable. Otherwise issuance can silently disclose a whole parent
/// claim instead of the requested leaf.
/// </summary>
public class NestedSelectivePathAdmissionTests
{
    private readonly SdJwtIssuer _issuer = TestHelpers.CreateIssuer();
    private readonly byte[] _signingKey = RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void Should_RejectMissingBase_When_NestedPathRequested()
    {
        var claims = new Dictionary<string, object> { ["sub"] = "holder-1" };

        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["profile.email"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("profile.email", exception.Message);
    }

    [Fact]
    public void Should_RejectMissingLeaf_When_NestedPathRequested()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { email = "alice@example.com" }
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["profile.phone"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("profile.phone", exception.Message);
    }

    [Fact]
    public void Should_RejectScalarIntermediate_When_DeepPathRequested()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { contact = "private contact string" }
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["profile.contact.email"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("profile.contact.email", exception.Message);
    }

    [Fact]
    public void Should_RejectNullIntermediate_When_DeepPathRequested()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { contact = (object?)null }
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["profile.contact.email"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("profile.contact.email", exception.Message);
    }

    [Fact]
    public void Should_RejectArrayIntermediate_When_DeepObjectPathRequested()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { contact = new[] { "alice@example.com" } }
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["profile.contact.email"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("profile.contact.email", exception.Message);
    }

    [Fact]
    public void Should_RejectMissingDeepLeaf_When_DeepPathRequested()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { contact = new { phone = "secret" } }
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["profile.contact.email"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("profile.contact.email", exception.Message);
    }

    [Fact]
    public void Should_RejectEntireIssuance_When_OneOfTwoNestedPathsIsMissing()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { email = "alice@example.com" }
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(
                claims,
                ["profile.email", "profile.phone"],
                _signingKey,
                HashAlgorithm.Sha256));

        Assert.Contains("profile.phone", exception.Message);
    }

    [Fact]
    public void Should_PreserveParentDisclosures_When_DeepPathExists()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { contact = new { email = "alice@example.com", phone = "secret" } }
        };

        var sdJwt = _issuer.CreateSdJwt(
            claims,
            ["profile.contact.email"],
            _signingKey,
            HashAlgorithm.Sha256);

        var presentation = new SdJwtPresenter().CreatePresentation(sdJwt, ["profile.contact.email"]);

        Assert.Equal(2, sdJwt.Disclosures.Count);
        Assert.Equal(2, presentation.SelectedDisclosures.Count);
    }
}
