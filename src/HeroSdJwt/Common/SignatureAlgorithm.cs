namespace HeroSdJwt.Common;

/// <summary>
/// Supported JWT signature algorithms per RFC 7518.
/// </summary>
public enum SignatureAlgorithm
{
    /// <summary>
    /// HMAC using SHA-256 (symmetric key).
    /// Requires a shared secret key.
    /// </summary>
    HS256,

    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-256 (asymmetric key).
    /// Requires RSA private key for signing, public key for verification.
    /// Minimum 2048-bit key size recommended.
    /// </summary>
    RS256,

    /// <summary>
    /// ECDSA using P-256 curve and SHA-256 (asymmetric key).
    /// Requires EC private key for signing, public key for verification.
    /// Uses secp256r1 (NIST P-256) curve.
    /// </summary>
    ES256
}
