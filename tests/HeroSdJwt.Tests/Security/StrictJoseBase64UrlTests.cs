using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// JOSE compact components must use unpadded base64url without whitespace.
/// A permissive decoder must not admit alternate spellings of the same bytes.
/// </summary>
public class StrictJoseBase64UrlTests
{
    [Theory]
    [InlineData("Zg==")]
    [InlineData("Zg=")]
    [InlineData("Zg ")]
    [InlineData(" Zg")]
    [InlineData("Zg\n")]
    [InlineData("Zg\r\n")]
    [InlineData("\tZg")]
    public void Should_RejectPaddingAndWhitespaceInEncodedComponents(string encoded)
    {
        var bytesError = Assert.Throws<SdJwtException>(() => Base64UrlEncoder.DecodeBytes(encoded));
        Assert.Equal(ErrorCode.InvalidInput, bytesError.ErrorCode);

        var textError = Assert.Throws<SdJwtException>(() => Base64UrlEncoder.DecodeString(encoded));
        Assert.Equal(ErrorCode.InvalidInput, textError.ErrorCode);
    }

    [Theory]
    [InlineData("Zg", "f")]
    [InlineData("Zm8", "fo")]
    [InlineData("Zm9v", "foo")]
    [InlineData("", "")]
    public void Should_DecodeCanonicalUnpaddedComponents(string encoded, string expected)
    {
        Assert.Equal(expected, Base64UrlEncoder.DecodeString(encoded));
    }
}
