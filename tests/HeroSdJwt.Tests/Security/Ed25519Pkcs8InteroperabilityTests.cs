using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 8410 wraps an Ed25519 seed in two OCTET STRINGs inside PKCS#8.
/// External key stores commonly export that format instead of the library's
/// legacy 64-byte seed-plus-public-key representation.
/// </summary>
public sealed class Ed25519Pkcs8InteroperabilityTests
{
    [Fact]
    public void Should_CreateIdenticalEdDsaSignature_FromRfc8410Pkcs8OrExpandedPrivateKey()
    {
        var (expandedPrivateKey, publicKey) = KeyGenerator.Instance.GenerateEd25519KeyPair();
        var pkcs8PrivateKey = EncodeRfc8410PrivateKey(expandedPrivateKey[..32]);
        var claims = new Dictionary<string, object> { ["sub"] = "pkcs8-test" };
        var signer = new JwtSigner();

        var expandedJwt = signer.CreateJwt(claims, expandedPrivateKey, SignatureAlgorithm.EdDSA);
        var pkcs8Jwt = signer.CreateJwt(claims, pkcs8PrivateKey, SignatureAlgorithm.EdDSA);

        Assert.Equal(expandedJwt, pkcs8Jwt);
        Assert.True(new SignatureValidator().VerifyJwtSignature(pkcs8Jwt, publicKey));
    }

    [Fact]
    public void Should_AllowRfc8410Pkcs8PrivateKeyThroughFluentIssuer()
    {
        var (expandedPrivateKey, publicKey) = KeyGenerator.Instance.GenerateEd25519KeyPair();
        var pkcs8PrivateKey = EncodeRfc8410PrivateKey(expandedPrivateKey[..32]);

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "pkcs8-test")
            .SignWithEd25519(pkcs8PrivateKey)
            .Build();

        var result = TestHelpers.CreateVerifier().TryVerifyPresentation(
            sdJwt.ToCombinedFormat(), publicKey);
        Assert.True(result.IsValid, result.ErrorDetails);
    }

    [Fact]
    public void Should_RejectOtherAlgorithmOidAndTrailingOrTruncatedPkcs8Bytes()
    {
        var (expandedPrivateKey, _) = KeyGenerator.Instance.GenerateEd25519KeyPair();
        var pkcs8 = EncodeRfc8410PrivateKey(expandedPrivateKey[..32]);
        var wrongOid = (byte[])pkcs8.Clone();
        wrongOid[11] = 0x6e; // X25519 OID (1.3.101.110), not Ed25519 (1.3.101.112).
        var extraByte = pkcs8.Concat(new byte[] { 0 }).ToArray();
        var truncated = pkcs8[..^1];
        var claims = new Dictionary<string, object> { ["sub"] = "pkcs8-test" };
        var signer = new JwtSigner();

        Assert.Throws<ArgumentException>(() => signer.CreateJwt(claims, wrongOid, SignatureAlgorithm.EdDSA));
        Assert.Throws<ArgumentException>(() => signer.CreateJwt(claims, extraByte, SignatureAlgorithm.EdDSA));
        Assert.Throws<ArgumentException>(() => signer.CreateJwt(claims, truncated, SignatureAlgorithm.EdDSA));
    }

    private static byte[] EncodeRfc8410PrivateKey(byte[] seed)
    {
        Assert.Equal(32, seed.Length);
        // PrivateKeyInfo version 0, Ed25519 OID, outer and inner OCTET STRING.
        return Convert.FromHexString("302e020100300506032b657004220420")
            .Concat(seed)
            .ToArray();
    }
}
