namespace HeroSdJwt.Primitives;

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
    ES256,

    /// <summary>
    /// EdDSA using Ed25519 curve (asymmetric key).
    /// Requires Ed25519 private key for signing, public key for verification.
    /// Provides 128-bit security with smaller keys and faster performance than RSA.
    /// Per RFC 8037.
    /// </summary>
    EdDSA,

    /// <summary>
    /// HMAC using SHA-384 (symmetric key).
    /// Requires a shared secret key.
    /// Minimum 384-bit key size recommended (same as hash output).
    /// Provides 192-bit security level.
    /// Per RFC 7518 Section 3.2.
    /// </summary>
    HS384,

    /// <summary>
    /// HMAC using SHA-512 (symmetric key).
    /// Requires a shared secret key.
    /// Minimum 512-bit key size recommended (same as hash output).
    /// Provides 256-bit security level.
    /// Per RFC 7518 Section 3.2.
    /// </summary>
    HS512,

    /// <summary>
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (asymmetric key).
    /// Requires RSA private key for signing, public key for verification.
    /// Minimum 2048-bit key size recommended.
    /// Provides provably secure padding (preferred over RS256 for new applications).
    /// Per RFC 7518 Section 3.5.
    /// </summary>
    PS256,

    /// <summary>
    /// ECDSA using P-384 curve and SHA-384 (asymmetric key).
    /// Requires EC private key for signing, public key for verification.
    /// Uses secp384r1 (NIST P-384) curve.
    /// Provides 192-bit security level.
    /// Per RFC 7518 Section 3.4.
    /// </summary>
    ES384,

    /// <summary>
    /// ECDSA using P-521 curve and SHA-512 (asymmetric key).
    /// Requires EC private key for signing, public key for verification.
    /// Uses secp521r1 (NIST P-521) curve.
    /// Provides 256-bit security level.
    /// Per RFC 7518 Section 3.4.
    /// </summary>
    ES512,

#if NET10_0_OR_GREATER
    /// <summary>
    /// ML-DSA-65 post-quantum digital signature algorithm (asymmetric key).
    /// Module-Lattice-Based Digital Signature Algorithm, security level 3.
    /// Provides ~192-bit classical security (equivalent to AES-192).
    /// Requires ML-DSA private key for signing, public key for verification.
    /// Per FIPS 204 (formerly CRYSTALS-Dilithium).
    /// Requires .NET 10 or later.
    /// </summary>
    MLDSA65,

    /// <summary>
    /// ML-DSA-87 post-quantum digital signature algorithm (asymmetric key).
    /// Module-Lattice-Based Digital Signature Algorithm, security level 5.
    /// Provides ~256-bit classical security (equivalent to AES-256).
    /// Requires ML-DSA private key for signing, public key for verification.
    /// Per FIPS 204 (formerly CRYSTALS-Dilithium).
    /// Requires .NET 10 or later.
    /// </summary>
    MLDSA87
#endif
}
