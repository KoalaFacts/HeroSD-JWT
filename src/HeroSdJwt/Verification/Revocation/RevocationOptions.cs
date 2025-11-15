namespace HeroSdJwt.Verification.Revocation;

/// <summary>
/// Configuration options for JWT token revocation during verification.
/// Revocation is always enabled when a RevocationStore is provided.
/// </summary>
public sealed class RevocationOptions
{
    /// <summary>
    /// Gets or sets the failure mode when revocation checks fail due to storage errors.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="RevocationFailureMode.FailClosed"/> (Default): Reject tokens if revocation
    /// check fails (secure default). Use this for security-first scenarios.
    /// </para>
    /// <para>
    /// <see cref="RevocationFailureMode.FailOpen"/>: Allow tokens if revocation check fails
    /// (availability-first). Use this only if high availability is critical and the
    /// risk of allowing revoked tokens during outages is acceptable.
    /// </para>
    /// </remarks>
    public RevocationFailureMode FailureMode { get; set; } = RevocationFailureMode.FailClosed;
}

/// <summary>
/// Defines the behavior when revocation checks fail due to storage errors or exceptions.
/// </summary>
public enum RevocationFailureMode
{
    /// <summary>
    /// Fail closed: Reject tokens if revocation check fails.
    /// This is the secure default that prioritizes security over availability.
    /// Use this when it's critical that revoked tokens are never accepted.
    /// </summary>
    FailClosed,

    /// <summary>
    /// Fail open: Allow tokens if revocation check fails.
    /// This prioritizes availability over security.
    /// Use this only if high availability is more important than the risk
    /// of accepting revoked tokens during storage outages.
    /// </summary>
    FailOpen
}
