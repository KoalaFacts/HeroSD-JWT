using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The wire-size limit is measured in UTF-8 bytes, not UTF-16 code units.
/// A direct model caller can supply non-ASCII text even though canonical JOSE
/// components are ASCII; serialization must never exceed its documented limit.
/// </summary>
public class PresentationUtf8ByteSizeTests
{
    [Fact]
    public void Should_RejectOversizedUtf8CombinedFormat_WhenSdJwtCharacterCountFits()
    {
        var disclosure = new string('\u00E9', Constants.MAX_JWT_SIZE_BYTES / 2);
        var sdJwt = new SdJwt("header.payload.signature", [disclosure], HashAlgorithm.Sha256);

        Assert.True(sdJwt.Jwt.Length + disclosure.Length + 2 < Constants.MAX_JWT_SIZE_BYTES);
        _ = Assert.Throws<ArgumentException>(sdJwt.ToCombinedFormat);
    }

    [Fact]
    public void Should_RejectOversizedUtf8CombinedFormat_WhenPresenterCharacterCountFits()
    {
        var disclosure = new string('\u00E9', Constants.MAX_JWT_SIZE_BYTES / 2);
        var presentation = new SdJwtPresentation("header.payload.signature", [disclosure]);

        Assert.True(presentation.Jwt.Length + disclosure.Length + 2 < Constants.MAX_JWT_SIZE_BYTES);
        _ = Assert.Throws<ArgumentException>(() => new SdJwtPresenter().FormatPresentation(presentation));
    }
}
