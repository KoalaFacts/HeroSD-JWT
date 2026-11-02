using HeroSdJwt.Models;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// SD-JWT construction must not exhaust an unbounded disclosure source before
/// the already-established verifier and presentation limits can reject it.
/// </summary>
public class SdJwtConstructorAdmissionTests
{
    [Fact]
    public void Should_RejectExcessDisclosures_DuringConstruction()
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt(
                "header.payload.signature",
                Enumerable.Repeat("W10", Constants.MAX_DISCLOSURES + 1),
                HashAlgorithm.Sha256));

        Assert.Equal("disclosures", error.ParamName);
    }

    [Fact]
    public void Should_StopReadingLazySource_AfterFirstExcessDisclosure()
    {
        static IEnumerable<string> AdversarialStream()
        {
            for (var i = 0; i < Constants.MAX_DISCLOSURES + 1; i++)
            {
                yield return "W10";
            }

            throw new InvalidOperationException("Source was consumed beyond the wire limit.");
        }

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt("header.payload.signature", AdversarialStream(), HashAlgorithm.Sha256));
        Assert.Equal("disclosures", error.ParamName);
    }

    [Fact]
    public void Should_AcceptExactlyMaximumDisclosures()
    {
        var sdJwt = new SdJwt(
            "header.payload.signature",
            Enumerable.Repeat("W10", Constants.MAX_DISCLOSURES),
            HashAlgorithm.Sha256);

        Assert.Equal(Constants.MAX_DISCLOSURES, sdJwt.Disclosures.Count);
    }
}
