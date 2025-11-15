namespace HeroSdJwt.Verification.Revocation;

/// <summary>
/// Configuration options for JWT token revocation during verification.
/// </summary>
public sealed class RevocationOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether revocation checking is enabled.
    /// </summary>
    /// <remarks>
    /// When false, all revocation checks are skipped during verification.
    /// Default: false (revocation disabled).
    /// </remarks>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Gets or sets a value indicating whether tokens without a 'jti' claim
    /// should fail verification when JTI revocation is attempted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When true, tokens without a 'jti' claim will fail verification if any
    /// JTI revocation entries exist in the store.
    /// </para>
    /// <para>
    /// When false, tokens without a 'jti' claim will pass JTI revocation checks
    /// (they cannot be individually revoked).
    /// </para>
    /// <para>
    /// Default: true (require JTI for revocation).
    /// </para>
    /// </remarks>
    public bool RequireJtiForRevocation { get; set; } = true;

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
