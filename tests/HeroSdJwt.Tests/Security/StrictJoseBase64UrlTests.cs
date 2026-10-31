using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

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
    [InlineData("Zh")] // "Zg" (f) with nonzero trailing four bits
    [InlineData("Zm9")] // "Zm8" (fo) with nonzero trailing two bits
    [InlineData("AR")] // "AQ" (0x01) with nonzero trailing four bits
    public void Should_RejectNonzeroUnusedBitsInEncodedComponents(string encoded)
    {
        var bytesError = Assert.Throws<SdJwtException>(() => Base64UrlEncoder.DecodeBytes(encoded));
        Assert.Equal(ErrorCode.InvalidInput, bytesError.ErrorCode);

        var textError = Assert.Throws<SdJwtException>(() => Base64UrlEncoder.DecodeString(encoded));
        Assert.Equal(ErrorCode.InvalidInput, textError.ErrorCode);
    }

    [Fact]
    public void Should_RejectNoncanonicalSignatureEvenWhenItDecodesToTheSameMac()
    {
        // A 32-byte HS256 signature leaves two unused bits in its 43rd character.
        // Altering only those bits must not produce a second accepted JWT spelling.
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var input = Base64UrlEncoder.Encode("{\\"alg\\":\\"HS256\\"}") + "." +
            Base64UrlEncoder.Encode("{\\"sub\\":\\"user-123\\"}");
        var signature = Base64UrlEncoder.Encode(
            HMACSHA256.HashData(key, System.Text.Encoding.UTF8.GetBytes(input)));
        var lastValue = alphabet.IndexOf(signature[^1]);
        Assert.Equal(0, lastValue % 4);
        var aliasSignature = signature[..^1] + alphabet[lastValue + 1];
        var validator = new SignatureValidator();

        Assert.True(validator.VerifyJwtSignature(input + "." + signature, key));
        var exception = Assert.Throws<SdJwtException>(() =>
            validator.VerifyJwtSignature(input + "." + aliasSignature, key));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
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
