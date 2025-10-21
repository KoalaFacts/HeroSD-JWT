namespace HeroSdJwt.Common;

/// <summary>
/// Convenience static wrapper around KeyGenerator for simple scenarios.
/// For dependency injection and testing, use IKeyGenerator and KeyGenerator directly.
/// </summary>
/// <example>
/// Simple usage:
/// <code>
/// var key = CryptoHelpers.GenerateHmacKey();
/// </code>
///
/// DI-friendly usage:
/// <code>
/// public class MyService
/// {
///     private readonly IKeyGenerator _keyGenerator;
///
///     public MyService(IKeyGenerator keyGenerator)
///     {
///         _keyGenerator = keyGenerator;
///     }
///
///     public void DoWork()
///     {
///         var key = _keyGenerator.GenerateHmacKey();
///     }
/// }
/// </code>
/// </example>
public static class CryptoHelpers
{
    private static readonly IKeyGenerator _generator = KeyGenerator.Instance;

    /// <summary>
    /// Generates a cryptographically secure HMAC key for HS256 signature algorithm.
    /// </summary>
    /// <param name="bits">Key size in bits. Default is 256 bits (32 bytes), which is standard for HS256.</param>
    /// <returns>Randomly generated HMAC key.</returns>
    public static byte[] GenerateHmacKey(int bits = 256)
        => _generator.GenerateHmacKey(bits);

    /// <summary>
    /// Generates an RSA key pair for RS256 signature algorithm.
    /// </summary>
    /// <param name="keySizeBits">RSA key size in bits. Minimum 2048, default 2048.</param>
    /// <returns>Tuple of (privateKey, publicKey) in PKCS#8 and SubjectPublicKeyInfo formats.</returns>
    public static (byte[] privateKey, byte[] publicKey) GenerateRsaKeyPair(int keySizeBits = 2048)
        => _generator.GenerateRsaKeyPair(keySizeBits);

    /// <summary>
    /// Generates an ECDSA key pair for ES256 signature algorithm (P-256 curve).
    /// </summary>
    /// <returns>Tuple of (privateKey, publicKey) in PKCS#8 and SubjectPublicKeyInfo formats.</returns>
    public static (byte[] privateKey, byte[] publicKey) GenerateEcdsaKeyPair()
        => _generator.GenerateEcdsaKeyPair();

    /// <summary>
    /// Generates an ECDSA key pair for key binding (holder binding).
    /// This is a convenience method that's identical to GenerateEcdsaKeyPair()
    /// but named to clarify its intended use for key binding.
    /// </summary>
    /// <returns>Tuple of (holderPrivateKey, holderPublicKey) in PKCS#8 and SubjectPublicKeyInfo formats.</returns>
    public static (byte[] holderPrivateKey, byte[] holderPublicKey) GenerateKeyBindingKeyPair()
        => GenerateEcdsaKeyPair();
}
