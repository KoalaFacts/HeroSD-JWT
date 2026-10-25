namespace HeroSdJwt.Verification.ReplayProtection;

/// <summary>
/// In-memory implementation of <see cref="IJtiCache"/> for single-instance deployments.
/// Every admission and expiry removal is serialized so a live replay marker is never
/// evicted to make room for a different token. Capacity exhaustion fails closed.
/// </summary>
public class InMemoryJtiCache : IJtiCache, IDisposable
{
    private readonly Dictionary<JtiCacheKey, DateTimeOffset> _cache = [];
#if NET9_0_OR_GREATER
    private readonly Lock _sync = new();
#else
    private readonly object _sync = new();
#endif
    private readonly int _maxEntries;
    private readonly TimeProvider _timeProvider;
    private readonly Timer _cleanupTimer;
    private bool _disposed;

    /// <summary>
    /// Initializes an in-memory replay cache with the system clock.
    /// </summary>
    /// <param name="options">Replay protection configuration.</param>
    public InMemoryJtiCache(ReplayProtectionOptions options)
        : this(options, TimeProvider.System)
    {
    }

    // Clock injection keeps expiry and capacity boundary tests deterministic
    // without changing the public constructor or adding runtime dependencies.
    internal InMemoryJtiCache(ReplayProtectionOptions options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        options.Validate();

        _maxEntries = options.MaxCacheEntries;
        _timeProvider = timeProvider;
        _cleanupTimer = new Timer(
            CleanupExpiredEntries,
            null,
            TimeSpan.FromMinutes(5),
            TimeSpan.FromMinutes(5));
    }

    /// <summary>
    /// Atomically admits a new issuer/JTI pair or rejects an existing live marker.
    /// Throws instead of evicting a live marker when capacity is exhausted.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The cache has no free or expired slot; the presentation must be rejected.
    /// </exception>
    public Task<bool> TryAddAsync(string issuer, string jti, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        ValidateParameters(issuer, jti, ttl);
        cancellationToken.ThrowIfCancellationRequested();

        var cacheKey = new JtiCacheKey(issuer, jti);
        lock (_sync)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            var now = _timeProvider.GetUtcNow();
            var expiration = now.Add(ttl);

            if (_cache.TryGetValue(cacheKey, out var existingExpiration) && existingExpiration > now)
            {
                return Task.FromResult(false);
            }

            // All removals and inserts use this lock. An expiry check cannot
            // remove a replacement marker inserted by another caller.
            _ = _cache.Remove(cacheKey);

            if (_cache.Count >= _maxEntries)
            {
                RemoveExpiredEntries(now);
                if (_cache.Count >= _maxEntries)
                {
                    throw new InvalidOperationException(
                        "In-memory replay cache capacity reached; refusing to evict live JTI markers.");
                }
            }

            _cache.Add(cacheKey, expiration);
            return Task.FromResult(true);
        }
    }

    /// <summary>
    /// Checks whether the issuer/JTI pair has a live replay marker.
    /// </summary>
    public Task<bool> ExistsAsync(string issuer, string jti, CancellationToken cancellationToken = default)
    {
        ValidateKeyParts(issuer, jti);
        cancellationToken.ThrowIfCancellationRequested();
        var cacheKey = new JtiCacheKey(issuer, jti);
        lock (_sync)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            if (!_cache.TryGetValue(cacheKey, out var expiration))
            {
                return Task.FromResult(false);
            }

            if (expiration > _timeProvider.GetUtcNow())
            {
                return Task.FromResult(true);
            }

            _ = _cache.Remove(cacheKey);
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Explicitly removes an issuer/JTI pair. Only use for intended administrative resets.
    /// </summary>
    public Task RemoveAsync(string issuer, string jti, CancellationToken cancellationToken = default)
    {
        ValidateKeyParts(issuer, jti);
        cancellationToken.ThrowIfCancellationRequested();
        var cacheKey = new JtiCacheKey(issuer, jti);
        lock (_sync)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            _ = _cache.Remove(cacheKey);
            return Task.CompletedTask;
        }
    }

    private void CleanupExpiredEntries(object? state)
    {
        lock (_sync)
        {
            if (!_disposed)
            {
                RemoveExpiredEntries(_timeProvider.GetUtcNow());
            }
        }
    }

    // Called only while holding _sync.
    private void RemoveExpiredEntries(DateTimeOffset now)
    {
        var expiredKeys = _cache
            .Where(pair => pair.Value <= now)
            .Select(pair => pair.Key)
            .ToArray();

        foreach (var key in expiredKeys)
        {
            _ = _cache.Remove(key);
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(InMemoryJtiCache));
        }
    }

    private static void ValidateParameters(string issuer, string jti, TimeSpan ttl)
    {
        ValidateKeyParts(issuer, jti);

        if (ttl <= TimeSpan.Zero)
        {
            throw new ArgumentException("TTL must be positive", nameof(ttl));
        }
    }

    private static void ValidateKeyParts(string issuer, string jti)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(jti);

        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException("Issuer cannot be empty or whitespace", nameof(issuer));
        }

        if (string.IsNullOrWhiteSpace(jti))
        {
            throw new ArgumentException("JTI cannot be empty or whitespace", nameof(jti));
        }
    }

    /// <summary>
    /// Stops cleanup and releases the in-memory marker set.
    /// </summary>
    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _cache.Clear();
        }

        _cleanupTimer.Dispose();
    }
}
