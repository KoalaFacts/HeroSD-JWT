using HeroSdJwt.Primitives;

namespace HeroSdJwt.Exceptions;

/// <summary>
/// Exception thrown when a JWT replay attack is detected.
/// Indicates that a token with the same jti has already been verified.
/// </summary>
public class ReplayAttackException : SdJwtException
{
    /// <summary>
    /// Gets the JWT ID (jti) of the replayed token.
    /// </summary>
    public string Jti { get; }

    /// <summary>
    /// Gets the issuer (iss) of the replayed token.
    /// </summary>
    public string Issuer { get; }

    /// <summary>
    /// Gets the timestamp when the replay was detected.
    /// </summary>
    public DateTimeOffset DetectedAt { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ReplayAttackException"/> class.
    /// </summary>
    /// <param name="jti">The JWT ID that was replayed.</param>
    /// <param name="issuer">The issuer of the replayed token.</param>
    /// <param name="message">Optional custom error message.</param>
    public ReplayAttackException(
        string jti,
        string issuer,
        string? message = null)
        : base(
            message ?? $"Token replay detected: jti '{jti}' from issuer '{issuer}' has already been used",
            ErrorCode.ReplayAttack)
    {
        Jti = jti ?? throw new ArgumentNullException(nameof(jti));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        DetectedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Initializes a new instance with an inner exception.
    /// </summary>
    public ReplayAttackException(
        string jti,
        string issuer,
        string message,
        Exception innerException)
        : base(message, ErrorCode.ReplayAttack, innerException)
    {
        Jti = jti ?? throw new ArgumentNullException(nameof(jti));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        DetectedAt = DateTimeOffset.UtcNow;
    }
}
