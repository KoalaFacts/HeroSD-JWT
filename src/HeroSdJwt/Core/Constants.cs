namespace HeroSdJwt.Core;

/// <summary>
/// Contains constant values used throughout the SD-JWT library.
/// </summary>
public static class Constants
{
    /// <summary>
    /// The claim name for the selective disclosure array in the JWT payload.
    /// </summary>
    public const string SdClaimName = "_sd";

    /// <summary>
    /// The claim name for the hash algorithm in the JWT payload.
    /// </summary>
    public const string SdAlgClaimName = "_sd_alg";

    /// <summary>
    /// The claim name for the confirmation claim (holder's public key) in the JWT payload.
    /// Used for key binding.
    /// </summary>
    public const string CnfClaimName = "cnf";

    /// <summary>
    /// The claim name for nonce in the key binding JWT.
    /// </summary>
    public const string NonceClaimName = "nonce";

    /// <summary>
    /// The claim name for audience in the key binding JWT.
    /// </summary>
    public const string AudienceClaimName = "aud";

    /// <summary>
    /// The claim name for issued at time in the key binding JWT.
    /// </summary>
    public const string IssuedAtClaimName = "iat";

    /// <summary>
    /// The claim name for the SD-JWT hash in the key binding JWT.
    /// </summary>
    public const string SdHashClaimName = "sd_hash";

    /// <summary>
    /// The minimum recommended salt length in bytes (128 bits = 16 bytes).
    /// </summary>
    public const int MinimumSaltLengthBytes = 16;

    /// <summary>
    /// The maximum number of disclosures allowed in an SD-JWT presentation.
    /// Prevents DoS attacks via excessive disclosures.
    /// </summary>
    public const int MaxDisclosures = 100;

    /// <summary>
    /// The maximum size of a JWT string in bytes.
    /// Prevents DoS attacks via excessively large JWT payloads.
    /// </summary>
    public const int MaxJwtSizeBytes = 65536; // 64 KB

    /// <summary>
    /// Security-critical JWT claims that MUST NOT be selectively disclosable.
    /// Per SD-JWT spec section 5.3, these claims are critical for evaluating authenticity and validity.
    /// </summary>
    public static readonly IReadOnlySet<string> ReservedClaims = new HashSet<string>
    {
        "iss",   // Issuer - identifies who created the JWT
        "aud",   // Audience - identifies intended recipients
        "exp",   // Expiration - critical for validity window
        "nbf",   // Not Before - critical for validity window
        "cnf",   // Confirmation - holder public key for key binding
        "iat",   // Issued At - important for replay prevention
        "sub",   // Subject - often security-sensitive identity
        "jti",   // JWT ID - important for deduplication/tracking
        "_sd",   // Selective Disclosure array - internal SD-JWT claim
        "_sd_alg" // Hash algorithm - internal SD-JWT claim
    };

    /// <summary>
    /// Maximum age of key binding JWT in seconds (default: 5 minutes).
    /// KB-JWTs older than this are rejected to prevent replay attacks.
    /// </summary>
    public const int MaxKeyBindingJwtAgeSeconds = 300;

    /// <summary>
    /// The separator character used in combined SD-JWT presentation format.
    /// </summary>
    public const char CombinedFormatSeparator = '~';

    /// <summary>
    /// The default hash algorithm for SD-JWT.
    /// </summary>
    public const string DefaultHashAlgorithmName = "sha-256";

    /// <summary>
    /// Mapping of hash algorithm enum to string representation in JWT.
    /// </summary>
    public static readonly IReadOnlyDictionary<Common.HashAlgorithm, string> HashAlgorithmNames =
        new Dictionary<Common.HashAlgorithm, string>
        {
            { Common.HashAlgorithm.Sha256, "sha-256" },
            { Common.HashAlgorithm.Sha384, "sha-384" },
            { Common.HashAlgorithm.Sha512, "sha-512" }
        };

    /// <summary>
    /// Reverse mapping of hash algorithm string to enum.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, Common.HashAlgorithm> HashAlgorithmFromName =
        new Dictionary<string, Common.HashAlgorithm>
        {
            { "sha-256", Common.HashAlgorithm.Sha256 },
            { "sha-384", Common.HashAlgorithm.Sha384 },
            { "sha-512", Common.HashAlgorithm.Sha512 }
        };
}
