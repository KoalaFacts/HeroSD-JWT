using HeroSdJwt.Models;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Credential issuance can exceed the 100-disclosure presentation limit,
/// but a hostile lazy source must not exhaust memory without any ceiling.
/// </summary>
public class SdJwtConstructorAdmissionTests
{
    [Fact]
    public void Should_AllowMoreThanPresentationLimit_DuringCredentialConstruction()
    {
        var sdJwt = new SdJwt(
            "header.payload.signature",
            Enumerable.Repeat("W10", Constants.MAX_DISCLOSURES + 1),
            HashAlgorithm.Sha256);

        Assert.Equal(Constants.MAX_DISCLOSURES + 1, sdJwt.Disclosures.Count);
    }

    [Fact]
    public void Should_RejectUnboundedCredentialDisclosureCount()
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt(
                "header.payload.signature",
                Enumerable.Repeat("W10", SdJwt.MaximumCredentialDisclosures + 1),
                HashAlgorithm.Sha256));

        Assert.Equal("disclosures", error.ParamName);
    }

    [Fact]
    public void Should_StopReadingLazySource_AfterFirstExcessCredentialDisclosure()
    {
        static IEnumerable<string> AdversarialStream()
        {
            for (var i = 0; i < SdJwt.MaximumCredentialDisclosures + 1; i++)
            {
                yield return "W10";
            }

            throw new InvalidOperationException("Source was consumed beyond the credential limit.");
        }

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt("header.payload.signature", AdversarialStream(), HashAlgorithm.Sha256));
        Assert.Equal("disclosures", error.ParamName);
    }

    [Fact]
    public void Should_AcceptExactlyConservativeCredentialDisclosureLimit()
    {
        var sdJwt = new SdJwt(
            "header.payload.signature",
            Enumerable.Repeat("W10", SdJwt.MaximumCredentialDisclosures),
            HashAlgorithm.Sha256);

        Assert.Equal(SdJwt.MaximumCredentialDisclosures, sdJwt.Disclosures.Count);
    }
}
