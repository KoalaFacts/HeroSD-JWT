using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Cryptography;

/// <summary>
/// Integration tests for Ed25519 (EdDSA) support in JWT signing and verification.
/// </summary>
public class Ed25519IntegrationTests
{
    [Fact]
    public void Ed25519_GenerateKeys_SignJwt_VerifyJwt_Success()
    {
        // Arrange - Generate Ed25519 key pair
        var keyGenerator = KeyGenerator.Instance;
        var (privateKey, publicKey) = keyGenerator.GenerateEd25519KeyPair();

        // Verify key sizes
        Assert.Equal(64, privateKey.Length); // Expanded private key
        Assert.Equal(32, publicKey.Length); // Public key

        // Act - Create and sign JWT with EdDSA
        var signer = new JwtSigner();
        var payload = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "name", "Test User" },
            { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
        };

        var jwt = signer.CreateJwt(payload, privateKey, SignatureAlgorithm.EdDSA);

        // Verify JWT structure
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);

        // Verify signature with public key
        var validator = new SignatureValidator();
        var isValid = validator.VerifyJwtSignature(jwt, publicKey);

        // Assert
        Assert.True(isValid, "Ed25519 signature should verify successfully");
    }

    [Fact]
    public void Ed25519_SignJwt_VerifyWithWrongKey_ReturnsFalse()
    {
        // Arrange - Generate two different key pairs
        var keyGenerator = KeyGenerator.Instance;
        var (privateKey1, _) = keyGenerator.GenerateEd25519KeyPair();
        var (_, publicKey2) = keyGenerator.GenerateEd25519KeyPair();

        // Act - Sign with key1, verify with key2
        var signer = new JwtSigner();
        var payload = new Dictionary<string, object> { { "sub", "user123" } };
        var jwt = signer.CreateJwt(payload, privateKey1, SignatureAlgorithm.EdDSA);

        var validator = new SignatureValidator();
        var isValid = validator.VerifyJwtSignature(jwt, publicKey2);

        // Assert
        Assert.False(isValid, "Ed25519 signature with wrong key should fail verification");
    }

    [Fact]
    public void Ed25519_SignJwt_TamperedPayload_VerificationFails()
    {
        // Arrange
        var keyGenerator = KeyGenerator.Instance;
        var (privateKey, publicKey) = keyGenerator.GenerateEd25519KeyPair();

        var signer = new JwtSigner();
        var payload = new Dictionary<string, object> { { "sub", "user123" } };
        var jwt = signer.CreateJwt(payload, privateKey, SignatureAlgorithm.EdDSA);

        // Act - Tamper with the JWT payload
        var parts = jwt.Split('.');
        var tamperedPayload = parts[1] + "tampered";
        var tamperedJwt = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        var validator = new SignatureValidator();
        var isValid = validator.VerifyJwtSignature(tamperedJwt, publicKey);

        // Assert
        Assert.False(isValid, "Tampered Ed25519 JWT should fail verification");
    }

    [Fact]
    public void Ed25519_MultipleSignAndVerify_AllSucceed()
    {
        // Arrange
        var keyGenerator = KeyGenerator.Instance;
        var (privateKey, publicKey) = keyGenerator.GenerateEd25519KeyPair();
        var signer = new JwtSigner();
        var validator = new SignatureValidator();

        // Act & Assert - Sign and verify multiple JWTs
        for (int i = 0; i < 5; i++)
        {
            var payload = new Dictionary<string, object> { { "sub", $"user{i}" } };
            var jwt = signer.CreateJwt(payload, privateKey, SignatureAlgorithm.EdDSA);
            var isValid = validator.VerifyJwtSignature(jwt, publicKey);

            Assert.True(isValid, $"Ed25519 JWT {i} should verify successfully");
        }
    }
}
