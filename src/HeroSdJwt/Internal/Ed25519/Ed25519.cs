// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Curve25519 and Ed25519 by Dan Bernstein - public domain (Ref10 from SUPERCOP)

namespace HeroSdJwt.Internal.Ed25519;

/// <summary>
/// Ed25519 public key signature system.
///
/// This implementation is ported from Chaos.NaCl and uses:
/// - .NET's System.Security.Cryptography.SHA512 instead of custom SHA512
/// - PKCS#8 key format compatibility for JWT integration
///
/// Ed25519 is a public key signature system with 128-bit security based on
/// the 255-bit elliptic curve Curve25519 using Edwards coordinates.
/// </summary>
internal static class Ed25519
{
    /// <summary>
    /// Size of Ed25519 public keys in bytes (32 bytes).
    /// </summary>
    public const int PublicKeySizeInBytes = 32;

    /// <summary>
    /// Size of Ed25519 signatures in bytes (64 bytes).
    /// </summary>
    public const int SignatureSizeInBytes = 64;

    /// <summary>
    /// Size of expanded private keys in bytes (64 bytes).
    /// </summary>
    public const int ExpandedPrivateKeySizeInBytes = 64;

    /// <summary>
    /// Size of private key seeds in bytes (32 bytes).
    /// </summary>
    public const int PrivateKeySeedSizeInBytes = 32;

    /// <summary>
    /// Verifies an Ed25519 signature.
    /// </summary>
    /// <param name="signature">64-byte signature to verify.</param>
    /// <param name="message">Message that was signed.</param>
    /// <param name="publicKey">32-byte public key.</param>
    /// <returns>True if signature is valid, false otherwise.</returns>
    public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
    {
        if (signature == null)
            throw new ArgumentNullException(nameof(signature));
        if (message == null)
            throw new ArgumentNullException(nameof(message));
        if (publicKey == null)
            throw new ArgumentNullException(nameof(publicKey));
        if (signature.Length != SignatureSizeInBytes)
            throw new ArgumentException($"Signature must be {SignatureSizeInBytes} bytes", nameof(signature));
        if (publicKey.Length != PublicKeySizeInBytes)
            throw new ArgumentException($"Public key must be {PublicKeySizeInBytes} bytes", nameof(publicKey));

        return Ed25519Operations.CryptoSignVerify(signature, 0, message, 0, message.Length, publicKey, 0);
    }

    /// <summary>
    /// Signs a message using Ed25519.
    /// </summary>
    /// <param name="message">Message to sign.</param>
    /// <param name="expandedPrivateKey">64-byte expanded private key.</param>
    /// <returns>64-byte signature.</returns>
    public static byte[] Sign(byte[] message, byte[] expandedPrivateKey)
    {
        if (message == null)
            throw new ArgumentNullException(nameof(message));
        if (expandedPrivateKey == null)
            throw new ArgumentNullException(nameof(expandedPrivateKey));
        if (expandedPrivateKey.Length != ExpandedPrivateKeySizeInBytes)
            throw new ArgumentException($"Expanded private key must be {ExpandedPrivateKeySizeInBytes} bytes", nameof(expandedPrivateKey));

        var signature = new byte[SignatureSizeInBytes];
        Ed25519Operations.CryptoSign(signature, 0, message, 0, message.Length, expandedPrivateKey, 0);
        return signature;
    }

    /// <summary>
    /// Generates an Ed25519 key pair from a 32-byte seed.
    /// </summary>
    /// <param name="privateKeySeed">32-byte seed for key generation.</param>
    /// <returns>Tuple of (publicKey, expandedPrivateKey).</returns>
    public static (byte[] publicKey, byte[] expandedPrivateKey) KeyPairFromSeed(byte[] privateKeySeed)
    {
        if (privateKeySeed == null)
            throw new ArgumentNullException(nameof(privateKeySeed));
        if (privateKeySeed.Length != PrivateKeySeedSizeInBytes)
            throw new ArgumentException($"Private key seed must be {PrivateKeySeedSizeInBytes} bytes", nameof(privateKeySeed));

        var publicKey = new byte[PublicKeySizeInBytes];
        var expandedPrivateKey = new byte[ExpandedPrivateKeySizeInBytes];

        Ed25519Operations.CryptoSignKeypair(publicKey, 0, expandedPrivateKey, 0, privateKeySeed, 0);

        return (publicKey, expandedPrivateKey);
    }

    /// <summary>
    /// Derives a public key from a 32-byte seed.
    /// </summary>
    /// <param name="privateKeySeed">32-byte seed.</param>
    /// <returns>32-byte public key.</returns>
    public static byte[] PublicKeyFromSeed(byte[] privateKeySeed)
    {
        if (privateKeySeed == null)
            throw new ArgumentNullException(nameof(privateKeySeed));
        if (privateKeySeed.Length != PrivateKeySeedSizeInBytes)
            throw new ArgumentException($"Private key seed must be {PrivateKeySeedSizeInBytes} bytes", nameof(privateKeySeed));

        var publicKey = new byte[PublicKeySizeInBytes];
        var expandedPrivateKey = new byte[ExpandedPrivateKeySizeInBytes];

        Ed25519Operations.CryptoSignKeypair(publicKey, 0, expandedPrivateKey, 0, privateKeySeed, 0);

        return publicKey;
    }
}
