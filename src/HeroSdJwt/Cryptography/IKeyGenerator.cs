using HeroSdJwt.Primitives;

namespace HeroSdJwt.Cryptography;

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
    /// <returns>Key pair with private key and public key in PKCS#8 and SubjectPublicKeyInfo formats.</returns>
    KeyPair GenerateRsaKeyPair(int keySizeBits = 2048);

    /// <summary>
    /// Generates an ECDSA key pair for ES256 (P-256 curve).
    /// </summary>
    /// <returns>Key pair with private key and public key in PKCS#8 and SubjectPublicKeyInfo formats.</returns>
    KeyPair GenerateEcdsaKeyPair();

    /// <summary>
    /// Generates an Ed25519 key pair for EdDSA.
    /// </summary>
    /// <returns>Key pair with 64-byte expanded private key and 32-byte raw public key.</returns>
    KeyPair GenerateEd25519KeyPair();

    /// <summary>
    /// Generates an ML-DSA-65 key pair for post-quantum digital signatures.
    /// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) provides security level 3 (~192-bit classical equivalent).
    /// </summary>
    /// <returns>Key pair with ML-DSA-65 private key (~2,560 bytes) and public key (~1,952 bytes) in FIPS 204 format.</returns>
    /// <remarks>
    /// Requires .NET 10 or later.
    /// </remarks>
    KeyPair GenerateMlDsa65KeyPair();

    /// <summary>
    /// Generates an ML-DSA-87 key pair for post-quantum digital signatures.
    /// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) provides security level 5 (~256-bit classical equivalent).
    /// </summary>
    /// <returns>Key pair with ML-DSA-87 private key (~4,896 bytes) and public key (~2,592 bytes) in FIPS 204 format.</returns>
    /// <remarks>
    /// Requires .NET 10 or later.
    /// </remarks>
    KeyPair GenerateMlDsa87KeyPair();
}
