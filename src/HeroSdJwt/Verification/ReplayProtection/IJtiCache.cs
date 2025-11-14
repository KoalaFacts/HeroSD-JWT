namespace HeroSdJwt.Verification.ReplayProtection;

/// <summary>
/// Defines a cache for tracking JWT IDs (jti) to prevent replay attacks.
/// Implementations MUST be thread-safe and support atomic check-and-set operations.
/// </summary>
public interface IJtiCache
{
    /// <summary>
    /// Attempts to record a jti claim in the cache atomically.
    /// This operation MUST be atomic (check-and-set) to prevent race conditions.
    /// </summary>
    /// <param name="issuer">The token issuer (iss claim). MUST NOT be null or empty.</param>
    /// <param name="jti">The JWT ID (jti claim). MUST NOT be null or empty.</param>
    /// <param name="ttl">Time-to-live for the cache entry. MUST be positive.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>
    /// <c>true</c> if the jti was successfully recorded (first time seen).
    /// <c>false</c> if the jti already exists in cache (replay detected).
    /// </returns>
    /// <exception cref="ArgumentNullException">If issuer or jti is null.</exception>
    /// <exception cref="ArgumentException">If issuer or jti is empty, or ttl is non-positive.</exception>
    Task<bool> TryAddAsync(
        string issuer,
        string jti,
        TimeSpan ttl,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a jti exists in the cache without modifying it.
    /// Used for testing, diagnostics, and auditing.
    /// </summary>
    /// <param name="issuer">The token issuer (iss claim).</param>
    /// <param name="jti">The JWT ID (jti claim).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><c>true</c> if the jti exists in cache, otherwise <c>false</c>.</returns>
    Task<bool> ExistsAsync(
        string issuer,
        string jti,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a jti from the cache.
    /// Used for testing, administrative operations, and manual cache cleanup.
    /// </summary>
    /// <param name="issuer">The token issuer (iss claim).</param>
    /// <param name="jti">The JWT ID (jti claim).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Task representing the async operation.</returns>
    Task RemoveAsync(
        string issuer,
        string jti,
        CancellationToken cancellationToken = default);
}
