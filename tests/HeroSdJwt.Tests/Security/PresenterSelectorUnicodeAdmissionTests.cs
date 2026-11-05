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
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Should_RejectUnpairedSurrogatesBeforeSelectingDisclosure(int caseId)
    {
        // Build at runtime: attribute strings are serialized into metadata,
        // where malformed UTF-16 may be normalized before the test runs.
        var surrogate = new string((char)(caseId % 2 == 0 ? 0xD800 : 0xDC00), 1);
        var selector = caseId < 2 ? surrogate : $"prefix{surrogate}suffix";
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
