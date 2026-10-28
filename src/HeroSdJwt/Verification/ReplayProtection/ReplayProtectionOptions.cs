namespace HeroSdJwt.Verification.ReplayProtection;

/// <summary>
/// Configuration options for JWT replay attack prevention.
/// </summary>
public class ReplayProtectionOptions
{
    /// <summary>
    /// Gets or sets whether replay protection is enabled.
    /// Default: <c>false</c> (opt-in feature).
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Gets or sets the behavior when cache operations fail.
    /// Default: <c>FailClosed</c> (security over availability).
    /// </summary>
    public CacheFailureMode FailureMode { get; set; } = CacheFailureMode.FailClosed;

    /// <summary>
    /// Gets or sets the maximum number of jti entries to cache.
    /// Default: 1,000,000 entries (~200 MB memory).
    /// </summary>
    public int MaxCacheEntries { get; set; } = 1_000_000;

    /// <summary>
    /// Gets or sets the legacy default TTL value (1 hour).
    /// Missing or malformed exp claims are rejected when replay checking is enabled;
    /// a fallback TTL cannot safely protect an unbounded credential lifetime.
    /// Retained for compatibility with existing configurations.
    /// </summary>
    public TimeSpan DefaultTtl { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets the maximum supported lifetime of a replay marker.
    /// Credentials requiring longer marker retention are rejected, not truncated.
    /// Default: 24 hours (prevents unbounded cache growth).
    /// </summary>
    public TimeSpan MaximumTtl { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Gets or sets the clock skew tolerance for standalone replay validation.
    /// Integrated SD-JWT verification retains markers through the larger of this
    /// tolerance and the verifier's claim-validation clock skew.
    /// Default: 30 seconds (per security best practices).
    /// </summary>
    public TimeSpan ClockSkewTolerance { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets whether jti claim is required when replay protection is enabled.
    /// Default: <c>true</c> (fail verification if jti missing).
    /// </summary>
    public bool RequireJtiClaim { get; set; } = true;

    /// <summary>
    /// Validates the configuration options.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when configuration is invalid.</exception>
    public void Validate()
    {
        if (MaxCacheEntries <= 0)
        {
            throw new InvalidOperationException(
                $"MaxCacheEntries must be greater than 0. Got: {MaxCacheEntries}");
        }

        if (MaxCacheEntries > 100_000_000)
        {
            throw new InvalidOperationException(
                $"MaxCacheEntries must be less than 100,000,000 to prevent excessive memory usage. Got: {MaxCacheEntries}");
        }

        if (DefaultTtl <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"DefaultTtl must be greater than zero. Got: {DefaultTtl}");
        }

        if (MaximumTtl <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"MaximumTtl must be greater than zero. Got: {MaximumTtl}");
        }

        if (DefaultTtl > MaximumTtl)
        {
            throw new InvalidOperationException(
                $"DefaultTtl ({DefaultTtl}) must be less than or equal to MaximumTtl ({MaximumTtl})");
        }

        if (ClockSkewTolerance < TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"ClockSkewTolerance must be non-negative. Got: {ClockSkewTolerance}");
        }

        if (ClockSkewTolerance > TimeSpan.FromMinutes(5))
        {
            throw new InvalidOperationException(
                $"ClockSkewTolerance should not exceed 5 minutes for security. Got: {ClockSkewTolerance}");
        }
    }
}

/// <summary>
/// Defines behavior when cache operations fail.
/// </summary>
public enum CacheFailureMode
{
    /// <summary>
    /// Reject tokens when cache is unavailable (default).
    /// Prioritizes security over availability.
    /// </summary>
    FailClosed = 0,

    /// <summary>
    /// Allow tokens when cache is unavailable.
    /// Prioritizes availability over security. Use with caution.
    /// </summary>
    FailOpen = 1
}
