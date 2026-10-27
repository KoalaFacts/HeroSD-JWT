using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// PKCS#8 import accepts one ASN.1 key prefix and reports the consumed bytes.
/// A trailing payload must not be silently ignored when signing a credential.
/// </summary>
public class StrictPkcs8SigningKeyAdmissionTests
{
    [Theory]
    [InlineData(SignatureAlgorithm.RS256)]
    [InlineData(SignatureAlgorithm.PS256)]
    [InlineData(SignatureAlgorithm.ES256)]
    [InlineData(SignatureAlgorithm.ES384)]
    [InlineData(SignatureAlgorithm.ES512)]
    public void Should_RejectTrailingBytesAfterValidPkcs8PrivateKey(SignatureAlgorithm algorithm)
    {
        using AsymmetricAlgorithm key = algorithm switch
        {
            SignatureAlgorithm.RS256 or SignatureAlgorithm.PS256 => RSA.Create(2048),
            SignatureAlgorithm.ES256 => ECDsa.Create(ECCurve.NamedCurves.nistP256),
            SignatureAlgorithm.ES384 => ECDsa.Create(ECCurve.NamedCurves.nistP384),
            SignatureAlgorithm.ES512 => ECDsa.Create(ECCurve.NamedCurves.nistP521),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };

        var privateKey = key switch
        {
            RSA rsa => rsa.ExportPkcs8PrivateKey(),
            ECDsa ecdsa => ecdsa.ExportPkcs8PrivateKey(),
            _ => throw new InvalidOperationException()
        };
        var publicKey = key switch
        {
            RSA rsa => rsa.ExportSubjectPublicKeyInfo(),
            ECDsa ecdsa => ecdsa.ExportSubjectPublicKeyInfo(),
            _ => throw new InvalidOperationException()
        };
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "signed-subject",
            ["exp"] = 4102444800L
        };

        var signer = new JwtSigner();
        var validJwt = signer.CreateJwt(claims, privateKey, algorithm);
        Assert.True(new SignatureValidator().VerifyJwtSignature(validJwt, publicKey));

        foreach (var trailingByte in new byte[] { 0x00, 0x30, 0xFF })
        {
            byte[] malformed = [.. privateKey, trailingByte];
            Assert.Throws<ArgumentException>(() =>
                signer.CreateJwt(claims, malformed, algorithm));
        }
    }
}
