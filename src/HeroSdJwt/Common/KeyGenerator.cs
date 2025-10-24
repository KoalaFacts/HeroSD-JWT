using System.Security.Cryptography;

namespace HeroSdJwt.Common;

/// <summary>
/// Default implementation of IKeyGenerator using .NET BCL cryptographic primitives.
/// This class is thread-safe and can be used as a singleton.
/// </summary>
public class KeyGenerator : IKeyGenerator
{
    /// <summary>
    /// Singleton instance for convenience.
    /// </summary>
    public static readonly KeyGenerator Instance = new();

    /// <inheritdoc/>
    public byte[] GenerateHmacKey(int bits = 256)
    {
        if (bits <= 0 || bits % 8 != 0)
            throw new ArgumentException("Key size must be a positive multiple of 8", nameof(bits));

        var key = new byte[bits / 8];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    /// <inheritdoc/>
    public (byte[] privateKey, byte[] publicKey) GenerateRsaKeyPair(int keySizeBits = 2048)
    {
        if (keySizeBits < 2048)
            throw new ArgumentException("RSA key size must be at least 2048 bits for security", nameof(keySizeBits));

        using var rsa = RSA.Create(keySizeBits);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        return (privateKey, publicKey);
    }

    /// <inheritdoc/>
    public (byte[] privateKey, byte[] publicKey) GenerateEcdsaKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        return (privateKey, publicKey);
    }
}
