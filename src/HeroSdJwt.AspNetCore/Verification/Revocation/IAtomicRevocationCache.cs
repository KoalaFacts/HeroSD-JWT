using Microsoft.Extensions.Caching.Distributed;

namespace HeroSdJwt.AspNetCore.Verification.Revocation;

/// <summary>
/// Provides backend-atomic, monotonic expiration for distributed JTI revocations.
/// Ordinary <see cref="IDistributedCache"/> updates can shorten a live marker.
/// </summary>
public interface IAtomicRevocationCache : IDistributedCache
{
    /// <summary>
    /// Atomically creates a revocation marker or extends its absolute expiration.
    /// </summary>
    /// <param name="key">The marker key shared across every application instance.</param>
    /// <param name="value">Marker bytes to store for a new entry.</param>
    /// <param name="expiresAt">The minimum absolute UTC expiration to preserve.</param>
    /// <param name="cancellationToken">Cancellation for the backend operation.</param>
    /// <returns>A task for the committed atomic update.</returns>
    /// <remarks>
    /// This must be a single backend-atomic operation shared by all clients and nodes.
    /// It must never replace an existing later expiration with an earlier one,
    /// re-create an expired entry with an already elapsed expiration, or remove a
    /// permanent revocation marker. Do not emulate it with Get followed by Set,
    /// a process-local lock, or separate expiry commands. Propagate backend errors
    /// and cancellation; never report success when the outcome is uncertain.
    /// </remarks>
    Task SetOrExtendAsync(
        string key,
        byte[] value,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);
}
