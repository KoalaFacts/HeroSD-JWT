using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Holder-supplied claim selectors must have a single well-defined UTF-8
/// representation, even with an imported credential's cached path mapping.
/// </summary>
public sealed class PresenterSelectorUnicodeAdmissionTests
{
    [Theory]
    [InlineData("\uD800")]
    [InlineData("\uDC00")]
    [InlineData("prefix\uD800suffix")]
    [InlineData("prefix\uDC00suffix")]
    public void Should_RejectUnpairedSurrogatesBeforeSelectingDisclosure(string selector)
    {
        var credential = CreateCredential(selector);

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter().CreatePresentation(credential, [selector]));

        Assert.Equal("selectedClaimNames", error.ParamName);
    }

    [Fact]
    public void Should_AllowValidSupplementaryUnicodeSelector()
    {
        const string selector = "claim_\uD83D\uDE00";
        var credential = CreateCredential(selector);

        var presentation = new SdJwtPresenter().CreatePresentation(credential, [selector]);

        Assert.Equal("c2FsdA", Assert.Single(presentation.SelectedDisclosures));
    }

    private static SdJwt CreateCredential(string selector)
    {
        return new SdJwt(
            "a.b.c",
            ["c2FsdA"],
            HashAlgorithm.Sha256,
            claimPathMapping: new Dictionary<string, int>(StringComparer.Ordinal)
            {
                [selector] = 0
            });
    }
}
