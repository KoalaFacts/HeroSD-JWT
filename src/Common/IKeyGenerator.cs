namespace HeroSdJwt.Common;

/// <summary>
/// Interface for cryptographic key generation.
/// Allows for dependency injection and testing with mock implementations.
/// </summary>
public interface IKeyGenerator
{
    /// <summary>
    /// Generates a cryptographically secure HMAC key.
    /// </summary>
    /// <param name="bits">Key size in bits (default: 256).</param>
    /// <returns>Randomly generated HMAC key.</returns>
    byte[] GenerateHmacKey(int bits = 256);

    /// <summary>
    /// Generates an RSA key pair.
    /// </summary>
    /// <param name="keySizeBits">RSA key size in bits (minimum 2048, default 2048).</param>
    /// <returns>Tuple of (privateKey, publicKey) in PKCS#8 and SubjectPublicKeyInfo formats.</returns>
    (byte[] privateKey, byte[] publicKey) GenerateRsaKeyPair(int keySizeBits = 2048);

    /// <summary>
    /// Generates an ECDSA key pair for ES256 (P-256 curve).
    /// </summary>
    /// <returns>Tuple of (privateKey, publicKey) in PKCS#8 and SubjectPublicKeyInfo formats.</returns>
    (byte[] privateKey, byte[] publicKey) GenerateEcdsaKeyPair();
}
