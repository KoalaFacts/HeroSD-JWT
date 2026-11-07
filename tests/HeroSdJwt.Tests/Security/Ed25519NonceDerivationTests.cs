using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

public class Ed25519NonceDerivationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_DeriveNonceFromSeed_When_64ByteKeySuffixIsUntrusted(bool appendPublicKey)
    {
        // Some 64-byte Ed25519 private-key formats contain seed || publicKey.
        // The second half is then public information and must never determine
        // the signing nonce; the signing result must depend only on the seed.
        var keyPair = KeyGenerator.Instance.GenerateEd25519KeyPair();
        var suppliedKey = (byte[])keyPair.PrivateKey.Clone();

        try
        {
            if (appendPublicKey)
            {
                keyPair.PublicKey.CopyTo(suppliedKey, 32);
            }
            else
            {
                Array.Clear(suppliedKey, 32, 32);
            }

            var claims = new Dictionary<string, object> { ["sub"] = "holder" };
            var signer = new JwtSigner();
            var expected = signer.CreateJwt(claims, keyPair.PrivateKey, SignatureAlgorithm.EdDSA);
            var actual = signer.CreateJwt(claims, suppliedKey, SignatureAlgorithm.EdDSA);

            Assert.Equal(expected, actual);
            Assert.True(new SignatureValidator().VerifyJwtSignature(actual, keyPair.PublicKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(suppliedKey);
            CryptographicOperations.ZeroMemory(keyPair.PrivateKey);
        }
    }
}
