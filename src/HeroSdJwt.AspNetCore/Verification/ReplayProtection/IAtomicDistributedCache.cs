using Microsoft.Extensions.Caching.Distributed;

namespace HeroSdJwt.AspNetCore.Verification.ReplayProtection;

/// <summary>
/// A distributed cache with backend-atomic create-if-absent and expiration support.
/// Ordinary <see cref="IDistributedCache"/> read/write operations cannot provide this guarantee.
/// </summary>
public interface IAtomicDistributedCache : IDistributedCache
{
    /// <summary>
    /// Atomically creates an absent entry and sets its expiration in the same backend operation.
    /// </summary>
    /// <param name="key">The cache key shared by all application nodes.</param>
    /// <param name="value">The value to store.</param>
    /// <param name="ttl">The positive lifetime of a newly created entry.</param>
    /// <param name="cancellationToken">Cancellation for the backend operation.</param>
    /// <returns>
    /// <c>true</c> only if this call created the entry; <c>false</c> if a live entry already exists.
    /// A duplicate attempt must leave the existing value and expiration unchanged.
    /// </returns>
    /// <remarks>
    /// Expired entries must be treated as absent. The operation must be atomic across all
    /// clients and nodes, not merely within this process. Implementations must propagate
    /// backend errors and cancellation, never report success on an uncertain outcome, and
    /// never fall back to separate reads/writes. Cancellation or a lost response can occur
    /// after an insert commits; retaining that marker is the safe outcome.
    /// </remarks>
    Task<bool> TryAddAsync(string key, byte[] value, TimeSpan ttl, CancellationToken cancellationToken = default);
}
