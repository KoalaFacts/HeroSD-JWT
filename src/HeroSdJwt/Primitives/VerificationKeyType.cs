namespace HeroSdJwt.Primitives;

/// <summary>
/// Describes the expected type of verification key for JWT signature validation.
/// Used to prevent algorithm/key-type confusion (e.g., HMAC with public keys).
/// </summary>
public enum VerificationKeyType
{
    /// <summary>
    /// Verification key may be either symmetric or asymmetric.
    /// </summary>
    Either = 0,

    /// <summary>
    /// Verification key is a symmetric secret (for HS* algorithms).
    /// </summary>
    Symmetric = 1,

    /// <summary>
    /// Verification key is an asymmetric public key (for RS/PS/ES/EdDSA algorithms).
    /// </summary>
    Asymmetric = 2
}
