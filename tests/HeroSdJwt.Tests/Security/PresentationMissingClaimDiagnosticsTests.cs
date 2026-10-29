using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

public class PresentationMissingClaimDiagnosticsTests
{
    [Fact]
    public void Should_NotExposeOtherPrivateClaimPaths_WhenSelectionIsUnknown()
    {
        // An imported holder credential can contain paths the caller did not
        // select. Exception messages may be sent to logs or API clients.
        var credential = new SdJwt(
            "header.payload.signature",
            ["unused-disclosure"],
            HashAlgorithm.Sha256,
            claimPathMapping: new Dictionary<string, int>(StringComparer.Ordinal)
            {
                ["medical.privateDiagnosis"] = 0,
                ["employment.privateSalary"] = 0
            });

        var exception = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter().CreatePresentation(credential, ["missing-claim"]));

        Assert.Contains("missing-claim", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("medical.privateDiagnosis", exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("employment.privateSalary", exception.ToString(), StringComparison.Ordinal);
    }
}
