using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace HeroSdJwt.Tests.Unit.KeyBinding;

/// <summary>
/// Unit tests for KeyBindingGenerator.
/// Tests key binding JWT creation with holder's private key.
/// </summary>
public class KeyBindingGeneratorTests
{
    [Fact]
    public void CreateKeyBindingJwt_WithValidInputs_ReturnsSignedJwt()
    {
        // Arrange
        var generator = new KeyBindingGenerator();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();
        var sdJwtHash = "test_sd_jwt_hash";
        var audience = "https://verifier.example.com";
        var nonce = "random_nonce_12345";

        // Act
        var keyBindingJwt = generator.CreateKeyBindingJwt(
            privateKey,
            sdJwtHash,
            audience,
            nonce
        );

        // Assert
        Assert.NotNull(keyBindingJwt);
        Assert.NotEmpty(keyBindingJwt);

        // JWT should have 3 parts (header.payload.signature)
        var parts = keyBindingJwt.Split('.');
        Assert.Equal(3, parts.Length);
    }

    [Fact]
    public void CreateKeyBindingJwt_WithNullPrivateKey_ThrowsArgumentNullException()
    {
        // Arrange
        var generator = new KeyBindingGenerator();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            generator.CreateKeyBindingJwt(null!, "hash", "aud", "nonce"));
    }

    [Fact]
    public void CreateKeyBindingJwt_WithNullSdJwtHash_ThrowsArgumentNullException()
    {
        // Arrange
        var generator = new KeyBindingGenerator();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            generator.CreateKeyBindingJwt(privateKey, null!, "aud", "nonce"));
    }

    [Fact]
    public void CreateKeyBindingJwt_PayloadContainsSdHash()
    {
        // Arrange
        var generator = new KeyBindingGenerator();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();
        var sdJwtHash = "expected_hash_value";

        // Act
        var keyBindingJwt = generator.CreateKeyBindingJwt(
            privateKey,
            sdJwtHash,
            "https://verifier.example.com",
            "nonce123"
        );

        // Assert - Decode payload and verify sd_hash claim
        var parts = keyBindingJwt.Split('.');
        var payloadJson = System.Text.Encoding.UTF8.GetString(
            Convert.FromBase64String(parts[1].Replace('-', '+').Replace('_', '/').PadRight(parts[1].Length + (4 - parts[1].Length % 4) % 4, '=')));
        var payload = JsonDocument.Parse(payloadJson);

        Assert.True(payload.RootElement.TryGetProperty("sd_hash", out var sdHashElement));
        Assert.Equal(sdJwtHash, sdHashElement.GetString());
    }

    [Fact]
    public void CreateKeyBindingJwt_PayloadContainsAudience()
    {
        // Arrange
        var generator = new KeyBindingGenerator();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();
        var audience = "https://verifier.example.com";

        // Act
        var keyBindingJwt = generator.CreateKeyBindingJwt(
            privateKey,
            "hash",
            audience,
            "nonce"
        );

        // Assert
        var parts = keyBindingJwt.Split('.');
        var payloadJson = System.Text.Encoding.UTF8.GetString(
            Convert.FromBase64String(parts[1].Replace('-', '+').Replace('_', '/').PadRight(parts[1].Length + (4 - parts[1].Length % 4) % 4, '=')));
        var payload = JsonDocument.Parse(payloadJson);

        Assert.True(payload.RootElement.TryGetProperty("aud", out var audElement));
        Assert.Equal(audience, audElement.GetString());
    }

    [Fact]
    public void CreateKeyBindingJwt_PayloadContainsNonce()
    {
        // Arrange
        var generator = new KeyBindingGenerator();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();
        var nonce = "unique_nonce_value";

        // Act
        var keyBindingJwt = generator.CreateKeyBindingJwt(
            privateKey,
            "hash",
            "aud",
            nonce
        );

        // Assert
        var parts = keyBindingJwt.Split('.');
        var payloadJson = System.Text.Encoding.UTF8.GetString(
            Convert.FromBase64String(parts[1].Replace('-', '+').Replace('_', '/').PadRight(parts[1].Length + (4 - parts[1].Length % 4) % 4, '=')));
        var payload = JsonDocument.Parse(payloadJson);

        Assert.True(payload.RootElement.TryGetProperty("nonce", out var nonceElement));
        Assert.Equal(nonce, nonceElement.GetString());
    }

    [Fact]
    public void CreateKeyBindingJwt_PayloadContainsIat()
    {
        // Arrange
        var generator = new KeyBindingGenerator();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();
        var beforeCreation = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Act
        var keyBindingJwt = generator.CreateKeyBindingJwt(
            privateKey,
            "hash",
            "aud",
            "nonce"
        );

        var afterCreation = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Assert
        var parts = keyBindingJwt.Split('.');
        var payloadJson = System.Text.Encoding.UTF8.GetString(
            Convert.FromBase64String(parts[1].Replace('-', '+').Replace('_', '/').PadRight(parts[1].Length + (4 - parts[1].Length % 4) % 4, '=')));
        var payload = JsonDocument.Parse(payloadJson);

        Assert.True(payload.RootElement.TryGetProperty("iat", out var iatElement));
        var iat = iatElement.GetInt64();
        Assert.InRange(iat, beforeCreation, afterCreation);
    }

    [Fact]
    public void CreateKeyBindingJwt_HeaderContainsTypKbPlusJwt()
    {
        // Arrange
        var generator = new KeyBindingGenerator();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();

        // Act
        var keyBindingJwt = generator.CreateKeyBindingJwt(
            privateKey,
            "hash",
            "aud",
            "nonce"
        );

        // Assert - Header should have typ: "kb+jwt"
        var parts = keyBindingJwt.Split('.');
        var headerJson = System.Text.Encoding.UTF8.GetString(
            Convert.FromBase64String(parts[0].Replace('-', '+').Replace('_', '/').PadRight(parts[0].Length + (4 - parts[0].Length % 4) % 4, '=')));
        var header = JsonDocument.Parse(headerJson);

        Assert.True(header.RootElement.TryGetProperty("typ", out var typElement));
        Assert.Equal("kb+jwt", typElement.GetString());
    }
}
