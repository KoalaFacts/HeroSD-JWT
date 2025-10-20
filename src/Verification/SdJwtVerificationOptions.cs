using HeroSdJwt.Common;

namespace HeroSdJwt.Verification;

/// <summary>
/// Configuration options for SD-JWT presentation verification.
/// This class is immutable after construction to prevent race conditions.
/// </summary>
public class SdJwtVerificationOptions
{
    /// <summary>
    /// Gets the maximum allowed clock skew for temporal claim validation.
    /// Default is 5 minutes (300 seconds).
    /// Valid range: 0-300 seconds per constitution requirements.
    /// </summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets whether key binding JWT is required.
    /// When true, presentations without key binding will fail verification.
    /// Default is false (key binding is optional).
    /// </summary>
    public bool RequireKeyBinding { get; init; } = false;

    /// <summary>
    /// Gets the expected issuer (iss claim).
    /// When set, presentations with different issuer will fail verification.
    /// Default is null (issuer not validated).
    /// </summary>
    public string? ExpectedIssuer { get; init; }

    /// <summary>
    /// Gets the expected audience (aud claim).
    /// When set, presentations without this audience will fail verification.
    /// Default is null (audience not validated).
    /// </summary>
    public string? ExpectedAudience { get; init; }

    /// <summary>
    /// Gets the expected hash algorithm for disclosure digests.
    /// When set, presentations using different hash algorithm will fail verification.
    /// Default is null (any standard algorithm accepted).
    /// </summary>
    public HashAlgorithm? ExpectedHashAlgorithm { get; init; }

    /// <summary>
    /// Gets the expected nonce for key binding JWT validation.
    /// When set, key binding JWTs with different nonce will fail verification.
    /// Default is null (nonce not validated).
    /// </summary>
    public string? ExpectedNonce { get; init; }

    /// <summary>
    /// Validates the options and throws if configuration is invalid.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when clock skew exceeds maximum allowed value.</exception>
    public void Validate()
    {
        if (ClockSkew < TimeSpan.Zero)
        {
            throw new ArgumentException("Clock skew cannot be negative", nameof(ClockSkew));
        }

        if (ClockSkew > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentException(
                "Clock skew cannot exceed 5 minutes per security requirements",
                nameof(ClockSkew));
        }
    }
}
