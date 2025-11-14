using System.Collections.Concurrent;

namespace HeroSdJwt.Verification.ReplayProtection;

/// <summary>
/// In-memory implementation of IJtiCache using ConcurrentDictionary.
/// Suitable for single-instance deployments.
/// Thread-safe and provides atomic operations via ConcurrentDictionary.TryAdd.
/// </summary>
public class InMemoryJtiCache : IJtiCache, IDisposable
{
    private readonly ConcurrentDictionary<JtiCacheKey, DateTimeOffset> cache;
    private readonly ReplayProtectionOptions options;
    private readonly Timer? cleanupTimer;
    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryJtiCache"/> class.
    /// </summary>
    /// <param name="options">Configuration options for replay protection.</param>
    /// <exception cref="ArgumentNullException">Thrown when options is null.</exception>
    public InMemoryJtiCache(ReplayProtectionOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.cache = new ConcurrentDictionary<JtiCacheKey, DateTimeOffset>();

        // Start periodic cleanup timer (every 5 minutes)
        this.cleanupTimer = new Timer(
            CleanupExpiredEntries,
            null,
            TimeSpan.FromMinutes(5),
            TimeSpan.FromMinutes(5));
    }

    /// <summary>
    /// Attempts to add a jti to the cache atomically.
    /// </summary>
    public Task<bool> TryAddAsync(string issuer, string jti, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        ValidateParameters(issuer, jti, ttl);

        var cacheKey = new JtiCacheKey(issuer, jti);
        var now = DateTimeOffset.UtcNow;
        var expiration = now.Add(ttl);

        // Check if key exists and is expired - remove it first
        if (cache.TryGetValue(cacheKey, out var existingExpiration) && existingExpiration < now)
        {
            cache.TryRemove(cacheKey, out _);
        }

        // Atomic operation: TryAdd returns false if key already exists
        var wasAdded = cache.TryAdd(cacheKey, expiration);

        // Check capacity and evict if needed
        if (wasAdded && cache.Count > options.MaxCacheEntries)
        {
            EvictOldestEntries();
        }

        return Task.FromResult(wasAdded);
    }

    /// <summary>
    /// Checks if a jti exists in the cache.
    /// </summary>
    public Task<bool> ExistsAsync(string issuer, string jti, CancellationToken cancellationToken = default)
    {
        var cacheKey = new JtiCacheKey(issuer, jti);
        var exists = cache.TryGetValue(cacheKey, out var expiration);

        // If entry exists but expired, remove it and return false
        if (exists && expiration < DateTimeOffset.UtcNow)
        {
            cache.TryRemove(cacheKey, out _);
            return Task.FromResult(false);
        }

        return Task.FromResult(exists);
    }

    /// <summary>
    /// Removes a jti from the cache.
    /// </summary>
    public Task RemoveAsync(string issuer, string jti, CancellationToken cancellationToken = default)
    {
        var cacheKey = new JtiCacheKey(issuer, jti);
        cache.TryRemove(cacheKey, out _);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Periodic cleanup of expired entries.
    /// </summary>
    private void CleanupExpiredEntries(object? state)
    {
        if (disposed) return;

        var now = DateTimeOffset.UtcNow;
        var expiredKeys = cache
            .Where(kvp => kvp.Value < now)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredKeys)
        {
            cache.TryRemove(key, out _);
        }
    }

    /// <summary>
    /// LRU eviction when cache reaches capacity.
    /// Evicts oldest entries (by expiration time).
    /// </summary>
    private void EvictOldestEntries()
    {
        // Evict 10% of entries when capacity reached
        var evictionCount = (int)(options.MaxCacheEntries * 0.1);

        var oldestEntries = cache
            .OrderBy(kvp => kvp.Value)
            .Take(evictionCount)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in oldestEntries)
        {
            cache.TryRemove(key, out _);
        }
    }

    /// <summary>
    /// Validates input parameters.
    /// </summary>
    private static void ValidateParameters(string issuer, string jti, TimeSpan ttl)
    {
        if (issuer == null)
            throw new ArgumentNullException(nameof(issuer));

        if (jti == null)
            throw new ArgumentNullException(nameof(jti));

        if (string.IsNullOrWhiteSpace(issuer))
            throw new ArgumentException("Issuer cannot be empty or whitespace", nameof(issuer));

        if (string.IsNullOrWhiteSpace(jti))
            throw new ArgumentException("JTI cannot be empty or whitespace", nameof(jti));

        if (ttl <= TimeSpan.Zero)
            throw new ArgumentException("TTL must be positive", nameof(ttl));
    }

    /// <summary>
    /// Releases all resources used by the <see cref="InMemoryJtiCache"/>.
    /// Stops the cleanup timer and clears the cache.
    /// </summary>
    public void Dispose()
    {
        if (!disposed)
        {
            disposed = true;
            cleanupTimer?.Dispose();
            cache.Clear();
        }
    }
}
