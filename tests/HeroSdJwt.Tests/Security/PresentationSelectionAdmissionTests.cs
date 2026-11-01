using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Holder claim-selection requests are bounded independently from the number
/// of Disclosures carried by a credential.
/// </summary>
public class PresentationSelectionAdmissionTests
{
    [Fact]
    public void Should_StopEnumeratingExcessClaimSelectors_When_CreatingPresentation()
    {
        static IEnumerable<string> AdversarialSelectors()
        {
            for (var i = 0; i < Constants.MAX_DISCLOSURES + 1; i++)
            {
                yield return "name";
            }

            throw new InvalidOperationException("Selector source was consumed past the presentation limit.");
        }

        var sdJwt = CreateCredential(1);
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter().CreatePresentation(sdJwt, AdversarialSelectors()));

        Assert.Equal("selectedClaimNames", error.ParamName);
    }

    [Fact]
    public void Should_AllowMaximumClaimSelectors_When_CreatingPresentation()
    {
        var presentation = new SdJwtPresenter().CreatePresentation(
            CreateCredential(1),
            Enumerable.Repeat("name", Constants.MAX_DISCLOSURES));

        Assert.Equal("W10", Assert.Single(presentation.SelectedDisclosures));
    }

    [Fact]
    public void Should_AllowCredentialWithMoreThanPresentationLimit_When_SelectingSubset()
    {
        // The presentation limit must not also become an issuance limit:
        // a holder can reveal a subset of a credential's many disclosures.
        var presentation = new SdJwtPresenter().CreatePresentation(
            CreateCredential(Constants.MAX_DISCLOSURES + 1),
            ["name"]);

        Assert.Equal("W10", Assert.Single(presentation.SelectedDisclosures));
        Assert.Equal("header.payload.signature~W10~", new SdJwtPresenter().FormatPresentation(presentation));
    }

    private static SdJwt CreateCredential(int disclosureCount) =>
        new(
            "header.payload.signature",
            Enumerable.Repeat("W10", disclosureCount),
            HashAlgorithm.Sha256,
            claimPathMapping: new Dictionary<string, int>(StringComparer.Ordinal)
            {
                ["name"] = 0
            });
}
