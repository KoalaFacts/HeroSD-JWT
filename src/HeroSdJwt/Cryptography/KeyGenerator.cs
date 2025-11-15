using HeroSdJwt.Internal.Ed25519;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;

namespace HeroSdJwt.Cryptography;

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
    public KeyPair GenerateRsaKeyPair(int keySizeBits = 2048)
    {
        if (keySizeBits < 2048)
            throw new ArgumentException("RSA key size must be at least 2048 bits for security", nameof(keySizeBits));

        using var rsa = RSA.Create(keySizeBits);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        return new KeyPair(privateKey, publicKey);
    }

    /// <inheritdoc/>
    public KeyPair GenerateEcdsaKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        return new KeyPair(privateKey, publicKey);
    }

    /// <inheritdoc/>
    public KeyPair GenerateEd25519KeyPair()
    {
        // Generate a random 32-byte seed
        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed);

        // Generate Ed25519 key pair from seed
        var publicKey = new byte[32];
        var expandedPrivateKey = new byte[64];

        Ed25519Operations.CryptoSignKeypair(publicKey, 0, expandedPrivateKey, 0, seed, 0);

        return new KeyPair(expandedPrivateKey, publicKey);
    }

#if NET10_0_OR_GREATER
    /// <inheritdoc/>
    public KeyPair GenerateMlDsa65KeyPair()
    {
        // ML-DSA-65 key generation using .NET 10 System.Security.Cryptography
        // FIPS 204 specifies ML-DSA with security parameter sets
        // ML-DSA-65: security level 3 (~192-bit classical strength)

        // Note: This is a placeholder for the actual .NET 10 API
        // The actual implementation will use System.Security.Cryptography.MLDsa65 or similar
        // when .NET 10 is released with PQC support

        throw new NotImplementedException(
            "ML-DSA-65 key generation requires .NET 10 with PQC support. " +
            "This is a preview implementation pending .NET 10 GA release.");

        // Expected implementation (when .NET 10 PQC APIs are available):
        // using var mlDsa = MLDsa65.Create();
        // var privateKey = mlDsa.ExportPrivateKey();
        // var publicKey = mlDsa.ExportPublicKey();
        // return new KeyPair(privateKey, publicKey);
    }

    /// <inheritdoc/>
    public KeyPair GenerateMlDsa87KeyPair()
    {
        // ML-DSA-87 key generation using .NET 10 System.Security.Cryptography
        // FIPS 204 specifies ML-DSA with security parameter sets
        // ML-DSA-87: security level 5 (~256-bit classical strength)

        // Note: This is a placeholder for the actual .NET 10 API
        // The actual implementation will use System.Security.Cryptography.MLDsa87 or similar
        // when .NET 10 is released with PQC support

        throw new NotImplementedException(
            "ML-DSA-87 key generation requires .NET 10 with PQC support. " +
            "This is a preview implementation pending .NET 10 GA release.");

        // Expected implementation (when .NET 10 PQC APIs are available):
        // using var mlDsa = MLDsa87.Create();
        // var privateKey = mlDsa.ExportPrivateKey();
        // var publicKey = mlDsa.ExportPublicKey();
        // return new KeyPair(privateKey, publicKey);
    }
#endif
}
