using HeroSdJwt.Common;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using System.Security.Cryptography;
using Xunit;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// Integration tests for SD-JWT with key binding (SD-JWT-KB).
/// </summary>
public class KeyBindingIntegrationTests
{
    [Fact]
    public void KeyBinding_CompleteFlow_CreatesAndValidates()
    {
        // Arrange - Generate keys
        var issuerKey = new byte[32];
        RandomNumberGenerator.Fill(issuerKey);

        using var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderPrivateKey = holderEcdsa.ExportECPrivateKey();
        var holderPublicKey = holderEcdsa.ExportSubjectPublicKeyInfo();

        // Create SD-JWT (issuer includes holder's public key in cnf claim)
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "user@example.com" },
            { "cnf", new { jwk = Convert.ToBase64String(holderPublicKey) } }
        };

        var issuer = new SdJwtIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            issuerKey,
            HashAlgorithm.Sha256
        );

        // Holder creates key binding JWT
        var kbGenerator = new KeyBindingGenerator();
        var sdJwtHash = Convert.ToBase64String(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sdJwt.Jwt)));
        var keyBindingJwt = kbGenerator.CreateKeyBindingJwt(
            holderPrivateKey,
            sdJwtHash,
            "https://verifier.example.com",
            "nonce123"
        );

        // Act - Validate key binding
        var isValid = KeyBindingValidator.ValidateKeyBinding(
            keyBindingJwt,
            holderPublicKey,
            sdJwtHash,
            "https://verifier.example.com",
            "nonce123"
        );

        // Assert
        Assert.True(isValid, "Key binding validation should succeed");
    }

    [Fact]
    public void KeyBinding_WithWrongKey_FailsValidation()
    {
        // Arrange
        using var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderPrivateKey = holderEcdsa.ExportECPrivateKey();

        using var wrongEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var wrongPublicKey = wrongEcdsa.ExportSubjectPublicKeyInfo();

        var kbGenerator = new KeyBindingGenerator();
        var sdJwtHash = "test_hash";
        var keyBindingJwt = kbGenerator.CreateKeyBindingJwt(
            holderPrivateKey,
            sdJwtHash,
            "aud",
            "nonce"
        );

        // Act - Validate with wrong public key
        var isValid = KeyBindingValidator.ValidateKeyBinding(
            keyBindingJwt,
            wrongPublicKey,
            sdJwtHash
        );

        // Assert
        Assert.False(isValid, "Key binding with wrong key should fail");
    }
}
