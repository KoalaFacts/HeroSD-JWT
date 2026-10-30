using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 7518 Section 3.2 requires HMAC keys at least as long as the hash output.
/// The public key generator must not produce keys that every supported HMAC
/// signer rejects as too weak.
/// </summary>
public class GeneratedHmacKeyStrengthTests
{
    [Theory]
    [InlineData(8)]
    [InlineData(128)]
    [InlineData(248)]
    public void Should_RejectHmacKeySizesBelowTheHs256Minimum(int bits)
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            KeyGenerator.Instance.GenerateHmacKey(bits));

        Assert.Equal("bits", exception.ParamName);
    }

    [Theory]
    [InlineData(256, SignatureAlgorithm.HS256)]
    [InlineData(384, SignatureAlgorithm.HS384)]
    [InlineData(512, SignatureAlgorithm.HS512)]
    public void Should_GenerateKeysUsableBySupportedHmacAlgorithms(int bits, SignatureAlgorithm algorithm)
    {
        var key = KeyGenerator.Instance.GenerateHmacKey(bits);
        Assert.Equal(bits / 8, key.Length);

        var jwt = new JwtSigner().CreateJwt(
            new Dictionary<string, object> { ["exp"] = 4102444800L },
            key,
            algorithm);

        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, key));
    }
}
