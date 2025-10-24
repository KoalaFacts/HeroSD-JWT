namespace HeroSdJwt.Common;

/// <summary>
/// Enumeration of error codes for SD-JWT operations.
/// Used for programmatic error handling.
/// </summary>
public enum ErrorCode
{
    /// <summary>
    /// JWT signature verification failed.
    /// The signature does not match the signed content.
    /// </summary>
    InvalidSignature,

    /// <summary>
    /// Disclosure hash digest does not match the expected value.
    /// Indicates tampering or incorrect disclosure.
    /// </summary>
    DigestMismatch,

    /// <summary>
    /// Token has expired (current time is past the 'exp' claim).
    /// </summary>
    TokenExpired,

    /// <summary>
    /// Token is not yet valid (current time is before the 'nbf' claim).
    /// </summary>
    TokenNotYetValid,

    /// <summary>
    /// The signature algorithm specified in the JWT header is not supported.
    /// Only RS256, ES256, and HS256 are supported.
    /// </summary>
    UnsupportedAlgorithm,

    /// <summary>
    /// Disclosure document is malformed and cannot be parsed.
    /// Expected format: [salt, claim_name, claim_value]
    /// </summary>
    MalformedDisclosure,

    /// <summary>
    /// A required claim is missing from the disclosed claims.
    /// </summary>
    MissingRequiredClaim,

    /// <summary>
    /// Algorithm confusion attack detected.
    /// The JWT header specifies the 'none' algorithm, which is forbidden.
    /// </summary>
    AlgorithmConfusion,

    /// <summary>
    /// Key binding JWT signature verification failed.
    /// The holder does not possess the private key corresponding to the public key in the 'cnf' claim.
    /// </summary>
    KeyBindingInvalid,

    /// <summary>
    /// Invalid input provided to the operation.
    /// </summary>
    InvalidInput,

    /// <summary>
    /// Hash algorithm specified in '_sd_alg' claim does not match expected algorithm.
    /// </summary>
    HashAlgorithmMismatch
}
