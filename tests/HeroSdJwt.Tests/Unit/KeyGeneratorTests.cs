using HeroSdJwt.Cryptography;
using System.Security.Cryptography;
using Xunit;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for KeyGenerator cryptographic key generation.
/// </summary>
public class KeyGeneratorTests
{
    private readonly IKeyGenerator keyGenerator = KeyGenerator.Instance;

    [Fact]
    public void GenerateHmacKey_WithDefaultSize_Returns256BitKey()
    {
        // Act
        var key = keyGenerator.GenerateHmacKey();

        // Assert
        Assert.Equal(32, key.Length); // 256 bits = 32 bytes
    }

    [Fact]
    public void GenerateHmacKey_WithCustomSize_ReturnsCorrectSize()
    {
        // Act
        var key512 = keyGenerator.GenerateHmacKey(512);

        // Assert
        Assert.Equal(64, key512.Length); // 512 bits = 64 bytes
    }

    [Fact]
    public void GenerateHmacKey_MultipleCallsProduceDifferentKeys()
    {
        // Act
        var key1 = keyGenerator.GenerateHmacKey();
        var key2 = keyGenerator.GenerateHmacKey();

        // Assert
        Assert.NotEqual(key1, key2);
    }

    [Fact]
    public void GenerateHmacKey_WithInvalidSize_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => keyGenerator.GenerateHmacKey(0));
        Assert.Throws<ArgumentException>(() => keyGenerator.GenerateHmacKey(-1));
        Assert.Throws<ArgumentException>(() => keyGenerator.GenerateHmacKey(7)); // Not multiple of 8
    }

    [Fact]
    public void GenerateRsaKeyPair_WithDefaultSize_Returns2048BitKeys()
    {
        // Act
        var (privateKey, publicKey) = keyGenerator.GenerateRsaKeyPair();

        // Assert
        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.NotEmpty(privateKey);
        Assert.NotEmpty(publicKey);

        // Verify key can be imported
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKey, out _);
        Assert.Equal(2048, rsa.KeySize);
    }

    [Fact]
    public void GenerateRsaKeyPair_WithCustomSize_ReturnsCorrectSize()
    {
        // Act
        var (privateKey, publicKey) = keyGenerator.GenerateRsaKeyPair(4096);

        // Assert
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKey, out _);
        Assert.Equal(4096, rsa.KeySize);
    }

    [Fact]
    public void GenerateRsaKeyPair_WithTooSmallSize_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            keyGenerator.GenerateRsaKeyPair(1024));

        Assert.Contains("2048", exception.Message);
    }

    [Fact]
    public void GenerateRsaKeyPair_PublicKeyMatchesPrivateKey()
    {
        // Act
        var (privateKey, publicKey) = keyGenerator.GenerateRsaKeyPair();

        // Assert - Extract public key from private key and compare
        using var rsaPrivate = RSA.Create();
        rsaPrivate.ImportPkcs8PrivateKey(privateKey, out _);
        var derivedPublicKey = rsaPrivate.ExportSubjectPublicKeyInfo();

        Assert.Equal(publicKey, derivedPublicKey);
    }

    [Fact]
    public void GenerateEcdsaKeyPair_ReturnsP256Keys()
    {
        // Act
        var (privateKey, publicKey) = keyGenerator.GenerateEcdsaKeyPair();

        // Assert
        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.NotEmpty(privateKey);
        Assert.NotEmpty(publicKey);

        // Verify key is P-256
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(privateKey, out _);
        Assert.Equal(256, ecdsa.KeySize);
    }

    [Fact]
    public void GenerateEcdsaKeyPair_PublicKeyMatchesPrivateKey()
    {
        // Act
        var (privateKey, publicKey) = keyGenerator.GenerateEcdsaKeyPair();

        // Assert
        using var ecdsaPrivate = ECDsa.Create();
        ecdsaPrivate.ImportPkcs8PrivateKey(privateKey, out _);
        var derivedPublicKey = ecdsaPrivate.ExportSubjectPublicKeyInfo();

        Assert.Equal(publicKey, derivedPublicKey);
    }

    [Fact]
    public void GenerateEcdsaKeyPair_CanBeUsedForKeyBinding()
    {
        // Act - Key binding uses ECDSA keys
        var (holderPrivateKey, holderPublicKey) = keyGenerator.GenerateEcdsaKeyPair();

        // Assert - Should be valid P-256 ECDSA keys
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(holderPrivateKey, out _);
        Assert.Equal(256, ecdsa.KeySize);

        var derivedPublicKey = ecdsa.ExportSubjectPublicKeyInfo();
        Assert.Equal(holderPublicKey, derivedPublicKey);
    }

    [Fact]
    public void GenerateEcdsaKeyPair_MultipleCallsProduceDifferentKeys()
    {
        // Act
        var (privateKey1, publicKey1) = keyGenerator.GenerateEcdsaKeyPair();
        var (privateKey2, publicKey2) = keyGenerator.GenerateEcdsaKeyPair();

        // Assert
        Assert.NotEqual(privateKey1, privateKey2);
        Assert.NotEqual(publicKey1, publicKey2);
    }

    [Fact]
    public void GenerateRsaKeyPair_MultipleCallsProduceDifferentKeys()
    {
        // Act
        var (privateKey1, publicKey1) = keyGenerator.GenerateRsaKeyPair();
        var (privateKey2, publicKey2) = keyGenerator.GenerateRsaKeyPair();

        // Assert
        Assert.NotEqual(privateKey1, privateKey2);
        Assert.NotEqual(publicKey1, publicKey2);
    }
}
