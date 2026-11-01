using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Presentation serialization must not emit a combined value that the library's
/// verifier rejects before cryptographic verification for size or slot count.
/// </summary>
public class PresentationSerializationAdmissionTests
{
    [Fact]
    public void Should_RejectOversizedCombinedPresentation_When_Formatting()
    {
        // JWT alone fits the verifier's size gate, but the separator and
        // selected disclosure put the combined presentation over the limit.
        var presentation = new SdJwtPresentation(
            new string('a', Constants.MAX_JWT_SIZE_BYTES - 1),
            ["W10"]);

        _ = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter().FormatPresentation(presentation));
    }

    [Fact]
    public void Should_RejectExcessDisclosureSlots_When_ConstructingPresentation()
    {
        _ = Assert.Throws<ArgumentException>(() => new SdJwtPresentation(
            "header.payload.signature",
            Enumerable.Repeat("W10", Constants.MAX_DISCLOSURES + 1)));
    }

    [Fact]
    public void Should_StopEnumeratingUnboundedDisclosures_AfterTheFirstExcessElement()
    {
        // A presentation cannot serialize more than MAX_DISCLOSURES. An untrusted
        // lazy IEnumerable must not be drained past that known-invalid count.
        static IEnumerable<string> AdversarialStream()
        {
            for (var i = 0; i < Constants.MAX_DISCLOSURES + 1; i++)
            {
                yield return "W10";
            }

            throw new InvalidOperationException("The stream was consumed past its admission limit.");
        }

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresentation("header.payload.signature", AdversarialStream()));
        Assert.Equal("selectedDisclosures", error.ParamName);
    }

    [Fact]
    public void Should_StopEnumeratingExcessDisclosures_When_ConstructingSdJwt()
    {
        // An untrusted lazy source must not be consumed beyond the 101st item.
        // The combined serializer already refuses more than MAX_DISCLOSURES.
        static IEnumerable<string> AdversarialStream()
        {
            for (var i = 0; i < Constants.MAX_DISCLOSURES + 1; i++)
            {
                yield return "W10";
            }

            throw new InvalidOperationException("The disclosure source was consumed after the limit.");
        }

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt("header.payload.signature", AdversarialStream(), HashAlgorithm.Sha256));
        Assert.Equal("disclosures", error.ParamName);
    }

    [Fact]
    public void Should_AllowMaximumDisclosureCount_When_ConstructingSdJwt()
    {
        var sdJwt = new SdJwt(
            "header.payload.signature",
            Enumerable.Repeat("W10", Constants.MAX_DISCLOSURES),
            HashAlgorithm.Sha256);

        Assert.Equal(Constants.MAX_DISCLOSURES, sdJwt.Disclosures.Count);
    }

    [Fact]
    public void Should_RejectOversizedCombinedPresentation_When_SerializingSdJwt()
    {
        var sdJwt = new SdJwt(
            new string('a', Constants.MAX_JWT_SIZE_BYTES - 1),
            ["W10"],
            HashAlgorithm.Sha256);

        _ = Assert.Throws<ArgumentException>(sdJwt.ToCombinedFormat);
    }

    [Fact]
    public void Should_RejectExcessDisclosureSlots_When_SerializingSdJwt()
    {
        var sdJwt = new SdJwt(
            "header.payload.signature",
            Enumerable.Repeat("W10", Constants.MAX_DISCLOSURES + 1),
            HashAlgorithm.Sha256);

        _ = Assert.Throws<ArgumentException>(sdJwt.ToCombinedFormat);
    }

    [Fact]
    public void Should_AllowExactCombinedSizeLimit_When_Serializing()
    {
        var jwt = new string('a', Constants.MAX_JWT_SIZE_BYTES - 1);
        var sdJwt = new SdJwt(jwt, [], HashAlgorithm.Sha256);
        var presentation = new SdJwtPresentation(jwt, []);

        Assert.Equal(Constants.MAX_JWT_SIZE_BYTES, sdJwt.ToCombinedFormat().Length);
        Assert.Equal(Constants.MAX_JWT_SIZE_BYTES, new SdJwtPresenter().FormatPresentation(presentation).Length);
    }
}
