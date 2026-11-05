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

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \t ")]
    public void Should_RejectInvalidSelectors_BeforeInvokingClaimPathMapper(string? selector)
    {
        var mapper = new CountingClaimPathMapper();
        var credential = new SdJwt(
            "header.payload.signature", ["W10"], HashAlgorithm.Sha256);

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter(mapper).CreatePresentation(credential, [selector!]));

        Assert.Equal("selectedClaimNames", error.ParamName);
        Assert.Equal(0, mapper.CallCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectSelectorsLargerThanPresentationByteLimit_BeforeMapping(bool useMultibyte)
    {
        // A single name cannot occur in a verifiable 64-KiB presentation.
        // Reject both oversized ASCII and shorter UTF-16 text exceeding
        // that budget when encoded as UTF-8.
        var selector = useMultibyte
            ? new string('é', Constants.MAX_JWT_SIZE_BYTES / 2 + 1)
            : new string('x', Constants.MAX_JWT_SIZE_BYTES + 1);
        var mapper = new CountingClaimPathMapper();
        var credential = new SdJwt(
            "header.payload.signature", ["W10"], HashAlgorithm.Sha256);

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter(mapper).CreatePresentation(credential, [selector]));

        Assert.Equal("selectedClaimNames", error.ParamName);
        Assert.Equal(0, mapper.CallCount);
    }

    private sealed class CountingClaimPathMapper : IDisclosureClaimPathMapper
    {
        public int CallCount { get; private set; }

        public Dictionary<string, int> BuildClaimPathMapping(SdJwt sdJwt)
        {
            CallCount++;
            return new Dictionary<string, int>(StringComparer.Ordinal);
        }
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
