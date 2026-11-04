using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// JOSE compact components must have a unique base64url spelling: unused
/// final sextet bits cannot create interchangeable signature encodings.
/// </summary>
public sealed class CanonicalJoseBase64UrlTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Repeat((byte)0x43, 32)];
    private const string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    [Theory]
    [InlineData("Zh")]
    [InlineData("Zm9")]
    public void DecodeBytes_WithNonZeroUnusedBits_RejectsNonCanonicalEncoding(string encoded)
    {
        var error = Assert.Throws<SdJwtException>(() => Base64UrlEncoder.DecodeBytes(encoded));
        Assert.Equal(ErrorCode.InvalidInput, error.ErrorCode);
    }

    [Theory]
    [InlineData("Zg", "f")]
    [InlineData("Zm8", "fo")]
    [InlineData("Zm9v", "foo")]
    public void DecodeBytes_WithCanonicalTail_AcceptsEncoding(string encoded, string expected)
    {
        Assert.Equal(Encoding.ASCII.GetBytes(expected), Base64UrlEncoder.DecodeBytes(encoded));
    }

    [Fact]
    public void VerifyPresentation_WithAliasedSignatureTail_RejectsPresentation()
    {
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "canonical-test")
            .SignWithHmac(_signingKey)
            .Build();

        // HS256 signatures contain 32 bytes: their 43-character base64url
        // representation has two unused low bits in its final sextet.
        var jwt = sdJwt.Jwt;
        var finalSextet = ALPHABET.IndexOf(jwt[^1]);
        Assert.InRange(finalSextet, 0, 60);
        Assert.Equal(0, finalSextet & 3);

        // Mutate only unused tail bits; the decoded signature bytes remain
        // identical. Such a textual alias must not verify as a JOSE component.
        var aliased = jwt[..^1] + ALPHABET[finalSextet + 1] + "~";
        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });

        var original = verifier.TryVerifyPresentation(jwt + "~", _signingKey);
        Assert.True(original.IsValid);

        var result = verifier.TryVerifyPresentation(aliased, _signingKey);
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
    }
}
