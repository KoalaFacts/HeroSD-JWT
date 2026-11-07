using HeroSdJwt.Cryptography;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 8410 Ed25519 public keys are exported as SubjectPublicKeyInfo by
/// ordinary key stores. Legacy 32-byte raw public keys must still work.
/// </summary>
public sealed class Ed25519SpkiInteroperabilityTests
{
    [Fact]
    public void Should_VerifyRfc8410SpkiPublicKey_InDirectAndFluentVerification()
    {
        var (privateKey, publicKey) = KeyGenerator.Instance.GenerateEd25519KeyPair();
        var spki = EncodeRfc8410SubjectPublicKeyInfo(publicKey);
        var signer = new JwtSigner();
        var claims = new Dictionary<string, object> { ["sub"] = "spki-test" };
        var jwt = signer.CreateJwt(claims, privateKey, SignatureAlgorithm.EdDSA);
        var validator = new SignatureValidator();

        Assert.True(validator.VerifyJwtSignature(jwt, publicKey));
        Assert.True(validator.VerifyJwtSignature(jwt, spki));

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "spki-test")
            .SignWithEd25519(privateKey)
            .Build();

        var result = TestHelpers.CreateVerifier().TryVerifyPresentation(
            sdJwt.ToCombinedFormat(), spki);
        Assert.True(result.IsValid, result.ErrorDetails);
    }

    [Fact]
    public void Should_RejectMalformedAndWrongAlgorithmEd25519Spki()
    {
        var (privateKey, publicKey) = KeyGenerator.Instance.GenerateEd25519KeyPair();
        var jwt = new JwtSigner().CreateJwt(
            new Dictionary<string, object> { ["sub"] = "spki-test" },
            privateKey, SignatureAlgorithm.EdDSA);
        var spki = EncodeRfc8410SubjectPublicKeyInfo(publicKey);

        var x25519Oid = (byte[])spki.Clone();
        x25519Oid[8] = 0x6e; // X25519 is not the Ed25519 signature algorithm.
        var unusedBits = (byte[])spki.Clone();
        unusedBits[11] = 1; // Ed25519 public keys have exactly 256 meaningful bits.
        var withNullParameters = new byte[14 + publicKey.Length];
        Convert.FromHexString("302c300706032b65700500032100").CopyTo(withNullParameters, 0);
        publicKey.CopyTo(withNullParameters, 14);

        byte[][] invalidKeys =
        [
            x25519Oid,
            unusedBits,
            withNullParameters,
            spki[..^1],
            [.. spki, 0]
        ];

        foreach (var invalidKey in invalidKeys)
        {
            var exception = Assert.Throws<SdJwtException>(
                () => new SignatureValidator().VerifyJwtSignature(jwt, invalidKey));
            Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
        }
    }

    [Fact]
    public void Should_RejectRfc8410SpkiOfDifferentEd25519Key()
    {
        var (privateKey, _) = KeyGenerator.Instance.GenerateEd25519KeyPair();
        var (_, unrelatedPublicKey) = KeyGenerator.Instance.GenerateEd25519KeyPair();
        var jwt = new JwtSigner().CreateJwt(
            new Dictionary<string, object> { ["sub"] = "spki-test" },
            privateKey, SignatureAlgorithm.EdDSA);

        Assert.False(new SignatureValidator().VerifyJwtSignature(
            jwt, EncodeRfc8410SubjectPublicKeyInfo(unrelatedPublicKey)));
    }

    private static byte[] EncodeRfc8410SubjectPublicKeyInfo(byte[] publicKey)
    {
        Assert.Equal(32, publicKey.Length);
        // DER: SubjectPublicKeyInfo, Ed25519 OID (no parameters), 0 unused bits.
        return [.. Convert.FromHexString("302a300506032b6570032100"), .. publicKey];
    }
}
