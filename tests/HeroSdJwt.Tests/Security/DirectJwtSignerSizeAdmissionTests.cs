using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Direct JWT issuance must not return signed tokens that the matching
/// standalone signature verifier rejects solely for exceeding its wire limit.
/// </summary>
public sealed class DirectJwtSignerSizeAdmissionTests
{
    [Theory]
    [InlineData(49_081)]
    [InlineData(50_000)]
    public void Should_RejectHmacJwtExceedingExistingVerifierWireLimit(int payloadLength)
    {
        var claims = new Dictionary<string, object>
        {
            ["data"] = new string('x', payloadLength)
        };

        // 49,081 characters exceed the limit by one byte after the HS256
        // signature is appended. The larger case exceeds it before signing.
        var exception = Assert.Throws<ArgumentException>(() =>
            new JwtSigner().CreateJwt(claims, new byte[32], SignatureAlgorithm.HS256));

        Assert.Contains("maximum allowed size", exception.Message);
    }

    [Fact]
    public void Should_RejectRsaJwtWhenLongerSignatureExceedsAvailableBudget()
    {
        var claims = new Dictionary<string, object>
        {
            ["data"] = new string('x', 48_960)
        };
        var signer = new JwtSigner();

        // The same payload fits with HS256, but a 2048-bit RSA signature
        // makes the final compact JWT exceed the 64-KiB verifier limit.
        var hmacJwt = signer.CreateJwt(claims, new byte[32], SignatureAlgorithm.HS256);
        Assert.True(hmacJwt.Length <= Constants.MAX_JWT_SIZE_BYTES);
        Assert.True(new SignatureValidator().VerifyJwtSignature(hmacJwt, new byte[32]));

        using var rsa = RSA.Create(2048);
        var exception = Assert.Throws<ArgumentException>(() =>
            signer.CreateJwt(claims, rsa.ExportPkcs8PrivateKey(), SignatureAlgorithm.RS256));

        Assert.Contains("maximum allowed size", exception.Message);
    }

    [Fact]
    public void Should_AllowJwtExactlyAtExistingVerifierWireLimit()
    {
        var claims = new Dictionary<string, object>
        {
            ["data"] = new string('x', 49_080)
        };
        var signingKey = new byte[32];

        var jwt = new JwtSigner().CreateJwt(claims, signingKey, SignatureAlgorithm.HS256);

        Assert.Equal(Constants.MAX_JWT_SIZE_BYTES, jwt.Length);
        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, signingKey));
    }
}
