using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

public class Ed25519SmallOrderPublicKeyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectSignatureForgery_When_PublicKeyIsEd25519Identity(bool useSpki)
    {
        // For the identity point A, the Ed25519 verification equation collapses
        // to [s]B = R regardless of the message. A signature with s=1 and R=B
        // must not authenticate an arbitrary JWT without a holder private key.
        byte[] identityPublicKey = new byte[32];
        identityPublicKey[0] = 1;

        byte[] forgedSignature = new byte[64];
        forgedSignature[0] = 0x58; // Compressed Ed25519 base point B.
        Array.Fill(forgedSignature, (byte)0x66, 1, 31);
        forgedSignature[32] = 1; // s=1, little endian.

        byte[] verificationKey = identityPublicKey;
        if (useSpki)
        {
            // RFC 8410 Ed25519 SPKI encoding accepted by the public verifier.
            byte[] spkiPrefix =
                [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];
            verificationKey = new byte[spkiPrefix.Length + identityPublicKey.Length];
            spkiPrefix.CopyTo(verificationKey, 0);
            identityPublicKey.CopyTo(verificationKey, spkiPrefix.Length);
        }

        var header = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { alg = "EdDSA", typ = "JWT" }));
        var payload = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { sub = "not-authorized" }));
        var jwt = $"{header}.{payload}.{Base64UrlEncoder.Encode(forgedSignature)}";

        Assert.False(new SignatureValidator().VerifyJwtSignature(jwt, verificationKey));
    }

    [Fact]
    public void Should_ContinueVerifyingValidEd25519Signatures()
    {
        var keyPair = KeyGenerator.Instance.GenerateEd25519KeyPair();
        var jwt = new JwtSigner().CreateJwt(
            new Dictionary<string, object> { ["sub"] = "valid-holder" },
            keyPair.PrivateKey,
            SignatureAlgorithm.EdDSA);

        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, keyPair.PublicKey));
    }
}
