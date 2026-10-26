using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Encoded JOSE JSON and SD-JWT disclosures must be UTF-8, not replacement-decoded text.
/// </summary>
public class MalformedUtf8EncodingTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public void Should_RejectMalformedUtf8InBase64UrlText()
    {
        byte[][] invalidSequences =
        [
            [0xff],
            [0xc3],
            [0xc0, 0xaf],
            [0xe2, 0x28, 0xa1],
            [0xed, 0xa0, 0x80]
        ];

        foreach (var bytes in invalidSequences)
        {
            var encoded = Base64UrlEncoder.Encode(bytes);

            // DecodeBytes remains intentionally lossless for arbitrary binary data.
            Assert.Equal(bytes, Base64UrlEncoder.DecodeBytes(encoded));

            var exception = Assert.Throws<SdJwtException>(() => Base64UrlEncoder.DecodeString(encoded));
            Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
        }
    }

    [Fact]
    public void Should_RejectMalformedUtf8InObjectDisclosure()
    {
        var malformedJson = InsertInvalidUtf8("[\"salt\",\"name\",\"", "\"]");
        var encoded = Base64UrlEncoder.Encode(malformedJson);

        var exception = Assert.Throws<SdJwtException>(() => new DisclosureParser().Parse(encoded));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Should_RejectSignedJwtWithMalformedUtf8InHeaderOrPayload(bool malformedHeader)
    {
        var expiration = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        byte[] header = malformedHeader
            ? InsertInvalidUtf8("{\"alg\":\"HS256\",\"kid\":\"utf8-key\",\"note\":\"", "\"}")
            : System.Text.Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"kid\":\"utf8-key\"}");
        byte[] payload = malformedHeader
            ? System.Text.Encoding.UTF8.GetBytes($"{{\"exp\":{expiration},\"sub\":\"valid\"}}")
            : InsertInvalidUtf8($"{{\"exp\":{expiration},\"sub\":\"", "\"}");

        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.ASCII.GetBytes(input));
        var presentation = input + "." + Base64UrlEncoder.Encode(signature) + "~";
        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        static byte[]? Resolver(string keyId)
        {
            return keyId == "utf8-key" ? _signingKey : null;
        }

        var resolved = verifier.TryVerifyPresentation(presentation, Resolver);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var thrown = Assert.Throws<SdJwtException>(() =>
        {
            _ = verifier.VerifyPresentation(presentation, _signingKey);
        });
        Assert.Equal(ErrorCode.InvalidInput, thrown.ErrorCode);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, Resolver, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);
    }

    private static byte[] InsertInvalidUtf8(string before, string after) =>
        [.. System.Text.Encoding.UTF8.GetBytes(before), 0xff, .. System.Text.Encoding.UTF8.GetBytes(after)];
}
