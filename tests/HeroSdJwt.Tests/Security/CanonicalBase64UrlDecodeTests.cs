using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Canonical base64url requires zero unused bits in the final sextet.
/// A decoder that only rejects padding or whitespace admits alternate spellings
/// of the same binary input, which is not valid canonical JOSE encoding.
/// </summary>
public sealed class CanonicalBase64UrlDecodeTests
{
    [Theory]
    [InlineData("Zh")]  // Same decoded byte as the canonical "Zg".
    [InlineData("Zm9")] // Same decoded bytes as the canonical "Zm8".
    public void Should_RejectNonzeroUnusedTailBits_FromPublicDecoder(string encoded)
    {
        var error = Assert.Throws<SdJwtException>(() => Base64UrlEncoder.DecodeBytes(encoded));
        Assert.Equal(ErrorCode.InvalidInput, error.ErrorCode);
    }

    [Theory]
    [InlineData("Zg", "f")]
    [InlineData("Zm8", "fo")]
    public void Should_AcceptCanonicalBase64UrlTailBits(string encoded, string expected)
    {
        Assert.Equal(expected, Base64UrlEncoder.DecodeString(encoded));
    }
}
