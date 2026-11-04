using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A Digest supplied to the public JWT signer is a JSON string value.
/// It must obey the same Unicode and size admission rules as every other
/// signed string, including when nested inside collections.
/// </summary>
public sealed class DirectJwtSignerDigestValueAdmissionTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Should_RejectInvalidUtf16_WhenDigestValueIsSigned(bool highSurrogate)
    {
        var invalid = highSurrogate ? new string((char)0xD800, 1) : new string((char)0xDC00, 1);
        var digest = new Digest(invalid, HashAlgorithm.Sha256);
        var claims = new Dictionary<string, object>[]
        {
            new() { ["digest"] = digest },
            new() { ["nested"] = new Dictionary<string, object> { ["digest"] = digest } },
            new() { ["items"] = new object[] { "safe", digest } }
        };

        foreach (var payload in claims)
        {
            var exception = Assert.Throws<ArgumentException>(() =>
                new JwtSigner().CreateJwt(payload, new byte[32], SignatureAlgorithm.HS256));

            Assert.Contains("invalid UTF-16", exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Should_RejectOversizedDigestBeforeGrowingJwtPayloadBuffer()
    {
        var digest = new Digest(new string('A', Constants.MAX_JWT_SIZE_BYTES + 1), HashAlgorithm.Sha256);
        var claims = new Dictionary<string, object> { ["digest"] = digest };

        var before = GC.GetAllocatedBytesForCurrentThread();
        var exception = Assert.Throws<ArgumentException>(() =>
            new JwtSigner().CreateJwt(claims, new byte[32], SignatureAlgorithm.HS256));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Contains("JWT claim JSON exceeds", exception.Message, StringComparison.Ordinal);
        Assert.True(allocated < 256 * 1024,
            $"Rejecting an oversized digest allocated {allocated} bytes before the signing size gate.");
    }

    [Fact]
    public void Should_PreserveValidDigest_WhenSigningDirectly()
    {
        var encoded = Base64UrlEncoder.Encode("a digest");
        var digest = new Digest(encoded, HashAlgorithm.Sha256);
        var jwt = new JwtSigner().CreateJwt(
            new Dictionary<string, object> { ["digest"] = digest },
            new byte[32],
            SignatureAlgorithm.HS256);

        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(jwt.Split('.')[1]));
        Assert.Equal(encoded, payload.RootElement.GetProperty("digest").GetProperty("...").GetString());
    }
}
