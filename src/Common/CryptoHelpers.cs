using System.Security.Cryptography;

namespace HeroSdJwt.Common;

/// <summary>
/// Helper methods for cryptographic key generation.
/// Simplifies creating keys for SD-JWT signing and key binding.
/// </summary>
public static class CryptoHelpers
{
    /// <summary>
    /// Generates a cryptographically secure HMAC key for HS256 signature algorithm.
    /// </summary>
    /// <param name="bits">Key size in bits. Default is 256 bits (32 bytes), which is standard for HS256.</param>
    /// <returns>Randomly generated HMAC key.</returns>
    /// <example>
    /// <code>
    /// var key = CryptoHelpers.GenerateHmacKey();
    /// var sdJwt = SdJwtBuilder.Create()
    ///     .WithClaims(claims)
    ///     .SignWithHmac(key)
    ///     .Build();
    /// </code>
    /// </example>
    public static byte[] GenerateHmacKey(int bits = 256)
    {
        if (bits <= 0 || bits % 8 != 0)
            throw new ArgumentException("Key size must be a positive multiple of 8", nameof(bits));

        var key = new byte[bits / 8];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    /// <summary>
    /// Generates an RSA key pair for RS256 signature algorithm.
    /// </summary>
    /// <param name="keySizeBits">RSA key size in bits. Minimum 2048, default 2048.</param>
    /// <returns>Tuple of (privateKey, publicKey) in PKCS#8 and SubjectPublicKeyInfo formats.</returns>
    /// <example>
    /// <code>
    /// var (privateKey, publicKey) = CryptoHelpers.GenerateRsaKeyPair();
    ///
    /// // Issuer creates SD-JWT
    /// var sdJwt = SdJwtBuilder.Create()
    ///     .WithClaims(claims)
    ///     .SignWithRsa(privateKey)
    ///     .Build();
    ///
    /// // Verifier uses public key
    /// var result = verifier.VerifyPresentation(presentation, publicKey);
    /// </code>
    /// </example>
    public static (byte[] privateKey, byte[] publicKey) GenerateRsaKeyPair(int keySizeBits = 2048)
    {
        if (keySizeBits < 2048)
            throw new ArgumentException("RSA key size must be at least 2048 bits for security", nameof(keySizeBits));

        using var rsa = RSA.Create(keySizeBits);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        return (privateKey, publicKey);
    }

    /// <summary>
    /// Generates an ECDSA key pair for ES256 signature algorithm (P-256 curve).
    /// </summary>
    /// <returns>Tuple of (privateKey, publicKey) in PKCS#8 and SubjectPublicKeyInfo formats.</returns>
    /// <example>
    /// <code>
    /// var (privateKey, publicKey) = CryptoHelpers.GenerateEcdsaKeyPair();
    ///
    /// // Issuer creates SD-JWT
    /// var sdJwt = SdJwtBuilder.Create()
    ///     .WithClaims(claims)
    ///     .SignWithEcdsa(privateKey)
    ///     .Build();
    ///
    /// // Verifier uses public key
    /// var result = verifier.VerifyPresentation(presentation, publicKey);
    /// </code>
    /// </example>
    public static (byte[] privateKey, byte[] publicKey) GenerateEcdsaKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        return (privateKey, publicKey);
    }

    /// <summary>
    /// Generates an ECDSA key pair for key binding (holder binding).
    /// This is a convenience method that's identical to GenerateEcdsaKeyPair()
    /// but named to clarify its intended use for key binding.
    /// </summary>
    /// <returns>Tuple of (holderPrivateKey, holderPublicKey) in PKCS#8 and SubjectPublicKeyInfo formats.</returns>
    /// <example>
    /// <code>
    /// var (holderPrivateKey, holderPublicKey) = CryptoHelpers.GenerateKeyBindingKeyPair();
    ///
    /// // Issuer embeds holder's public key
    /// var sdJwt = SdJwtBuilder.Create()
    ///     .WithClaims(claims)
    ///     .SignWithHmac(issuerKey)
    ///     .WithKeyBinding(holderPublicKey)
    ///     .Build();
    ///
    /// // Holder creates key binding JWT with private key
    /// var kbGenerator = new KeyBindingGenerator();
    /// var keyBindingJwt = kbGenerator.CreateKeyBindingJwt(holderPrivateKey, ...);
    /// </code>
    /// </example>
    public static (byte[] holderPrivateKey, byte[] holderPublicKey) GenerateKeyBindingKeyPair()
        => GenerateEcdsaKeyPair();
}
