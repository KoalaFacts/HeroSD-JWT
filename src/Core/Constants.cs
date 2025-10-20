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
