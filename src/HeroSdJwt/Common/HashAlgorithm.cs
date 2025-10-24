namespace HeroSdJwt.Common;

/// <summary>
/// Specifies the cryptographic hash algorithm used for SD-JWT digest computation.
/// </summary>
public enum HashAlgorithm
{
    /// <summary>
    /// SHA-256 hash algorithm (256-bit digest).
    /// Maps to "_sd_alg": "sha-256" in JWT payload.
    /// Default algorithm for SD-JWT.
    /// </summary>
    Sha256,

    /// <summary>
    /// SHA-384 hash algorithm (384-bit digest).
    /// Maps to "_sd_alg": "sha-384" in JWT payload.
    /// </summary>
    Sha384,

    /// <summary>
    /// SHA-512 hash algorithm (512-bit digest).
    /// Maps to "_sd_alg": "sha-512" in JWT payload.
    /// </summary>
    Sha512
}
