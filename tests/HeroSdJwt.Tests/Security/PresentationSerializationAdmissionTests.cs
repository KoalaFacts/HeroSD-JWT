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
    public void Should_RejectOversizedCombinedPresentation_When_Constructing()
    {
        // JWT alone fits, but one disclosure pushes the wire size over the
        // limit. Reject it while reading the source, not after materialization.
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresentation(
                new string('a', Constants.MAX_JWT_SIZE_BYTES - 1),
                ["W10"]));

        Assert.Equal("selectedDisclosures", error.ParamName);
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_StopConsumingDisclosureStream_When_CumulativeWireBudgetIsExceeded(bool useMultibyte)
    {
        // The first disclosure fits. The second overflows the combined wire
        // budget, either by UTF-16 length or by UTF-8 byte length.
        var disclosure = useMultibyte
            ? new string('\u00E9', Constants.MAX_JWT_SIZE_BYTES / 4)
            : new string('x', Constants.MAX_JWT_SIZE_BYTES / 2);
        var yielded = 0;

        IEnumerable<string> AdversarialStream()
        {
            yielded++;
            yield return disclosure;
            yielded++;
            yield return disclosure;
            throw new InvalidOperationException("The enumerator advanced past the wire budget.");
        }

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresentation("header.payload.signature", AdversarialStream()));

        Assert.Equal("selectedDisclosures", error.ParamName);
        Assert.Equal(2, yielded);
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
            new SdJwtPresentation(
                new string('a', Constants.MAX_JWT_SIZE_BYTES),
                Disclosures()));

        Assert.Equal("jwt", error.ParamName);
        Assert.False(enumerated);
    }

    [Fact]
    public void Should_RejectJwtWhoseUtf8BytesExceedPresentationLimit()
    {
        // 32-Ki UTF-16 code units occupy 64 KiB in UTF-8.
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresentation(
                new string('\u00e9', Constants.MAX_JWT_SIZE_BYTES / 2),
                []));

        Assert.Equal("jwt", error.ParamName);
    }

    [Fact]
    public void Should_RejectKeyBindingJwtThatCannotFitInAnyPresentation()
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresentation(
                "header.payload.signature",
                [],
                new string('a', Constants.MAX_JWT_SIZE_BYTES)));

        Assert.Equal("keyBindingJwt", error.ParamName);
    }

    [Fact]
    public void Should_RejectOversizedMinimumCombinedJwtAndKeyBinding()
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresentation(
                new string('a', Constants.MAX_JWT_SIZE_BYTES / 2),
                [],
                new string('b', Constants.MAX_JWT_SIZE_BYTES / 2)));

        Assert.Equal("keyBindingJwt", error.ParamName);
    }

}
