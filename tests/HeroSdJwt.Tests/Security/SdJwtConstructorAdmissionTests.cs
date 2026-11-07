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
                Enumerable.Repeat("W10", SdJwt.MAX_CREDENTIAL_DISCLOSURES + 1),
                HashAlgorithm.Sha256));

        Assert.Equal("disclosures", error.ParamName);
    }

    [Fact]
    public void Should_StopReadingLazySource_AfterFirstExcessCredentialDisclosure()
    {
        static IEnumerable<string> AdversarialStream()
        {
            for (var i = 0; i < SdJwt.MAX_CREDENTIAL_DISCLOSURES + 1; i++)
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
            Enumerable.Repeat("W10", SdJwt.MAX_CREDENTIAL_DISCLOSURES),
            HashAlgorithm.Sha256);

        Assert.Equal(SdJwt.MAX_CREDENTIAL_DISCLOSURES, sdJwt.Disclosures.Count);
    }

    [Fact]
    public void Should_RejectJwtThatCannotFitInAnyPresentation_BeforeReadingDisclosures()
    {
        var enumerated = false;

        IEnumerable<string> Disclosures()
        {
            enumerated = true;
            yield return "W10";
        }

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt(
                new string('a', Constants.MAX_JWT_SIZE_BYTES),
                Disclosures(),
                HashAlgorithm.Sha256));

        Assert.Equal("jwt", error.ParamName);
        Assert.False(enumerated);
    }

    [Fact]
    public void Should_RejectJwtWhoseUtf8BytesExceedPresentationLimit()
    {
        // A 32-Ki UTF-16 string occupies 64 KiB in UTF-8 before
        // even adding the mandatory combined-presentation separator.
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt(
                new string('\u00e9', Constants.MAX_JWT_SIZE_BYTES / 2),
                [],
                HashAlgorithm.Sha256));

        Assert.Equal("jwt", error.ParamName);
    }

    [Fact]
    public void Should_RejectKeyBindingJwtThatCannotFitInAnyPresentation()
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt(
                "header.payload.signature",
                [],
                HashAlgorithm.Sha256,
                keyBindingJwt: new string('a', Constants.MAX_JWT_SIZE_BYTES)));

        Assert.Equal("keyBindingJwt", error.ParamName);
    }

    [Fact]
    public void Should_RejectOversizedMinimumCombinedJwtAndKeyBinding()
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt(
                new string('a', Constants.MAX_JWT_SIZE_BYTES / 2),
                [],
                HashAlgorithm.Sha256,
                keyBindingJwt: new string('b', Constants.MAX_JWT_SIZE_BYTES / 2)));

        Assert.Equal("keyBindingJwt", error.ParamName);
    }
}
