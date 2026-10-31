using HeroSdJwt.Primitives;
using HeroSdJwt.Verification.Revocation;
using Microsoft.Extensions.Caching.Distributed;

namespace HeroSdJwt.AspNetCore.Verification.Revocation;

/// <summary>
/// Distributed <see cref="IRevocationStore"/> backed by <see cref="IDistributedCache"/> for multi-node deployments.
/// </summary>
public sealed class DistributedRevocationStore(IDistributedCache cache, string keyPrefix = "sdjwt:revocation") : IRevocationStore
{
    private readonly IDistributedCache _cache = cache ?? throw new ArgumentNullException(nameof(cache));
    private readonly string _keyPrefix = string.IsNullOrWhiteSpace(keyPrefix) ? "sdjwt:revocation" : keyPrefix.Trim();

    /// <inheritdoc />
    public async Task RevokeJtiAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ValidateId(jti, nameof(jti));
        cancellationToken.ThrowIfCancellationRequested();

        // The verifier may accept exp for up to five minutes of clock skew.
        // A revoked token must remain blocked throughout that same window.
        // Convert to UTC and saturate to avoid overflowing the timestamp.
        var utcExpiration = expiresAt.ToUniversalTime();
        var maximumSkew = TimeSpan.FromMinutes(5);
        var latestSafeExpiration = DateTimeOffset.MaxValue - maximumSkew;
        var retentionExpiresAt = utcExpiration > latestSafeExpiration
            ? DateTimeOffset.MaxValue
            : utcExpiration + maximumSkew;

        if (retentionExpiresAt <= DateTimeOffset.UtcNow)
        {
            // The token is no longer acceptable, even with maximum clock skew.
            return;
        }

        // A generic IDistributedCache.SetAsync overwrites the expiration of a
        // previous revocation. Concurrent callers with shorter expirations can
        // therefore re-admit an otherwise revoked, still-valid credential.
        // Only a backend-atomic monotonic expiration update is safe.
        if (_cache is not IAtomicRevocationCache atomicCache)
        {
            throw new NotSupportedException(
                "Distributed JTI revocation requires IAtomicRevocationCache with backend-atomic " +
                "create-or-extend expiration. Register a compliant provider or an IRevocationStore implementation.");
        }

        var key = BuildJtiKey(jti);
        await atomicCache.SetOrExtendAsync(
            key, MarkerBytes(), retentionExpiresAt, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> IsJtiRevokedAsync(string jti, CancellationToken cancellationToken = default)
    {
        ValidateId(jti, nameof(jti));
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildJtiKey(jti);
        var value = await _cache.GetAsync(key, cancellationToken).ConfigureAwait(false);
        return value != null;
    }

    /// <inheritdoc />
    public async Task RevokeKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        KeyIdValidator.Validate(keyId);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildKeyIdKey(keyId);
        await _cache.SetAsync(key, MarkerBytes(), new DistributedCacheEntryOptions(), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> IsKeyRevokedAsync(string keyId, CancellationToken cancellationToken = default)
    {
        KeyIdValidator.Validate(keyId);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildKeyIdKey(keyId);
        var value = await _cache.GetAsync(key, cancellationToken).ConfigureAwait(false);
        return value != null;
    }

    /// <inheritdoc />
    public Task UnrevokeKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        KeyIdValidator.Validate(keyId);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildKeyIdKey(keyId);
        return _cache.RemoveAsync(key, cancellationToken);
    }

    /// <inheritdoc />
    public async Task RevokeUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        ValidateId(userId, nameof(userId));
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildUserIdKey(userId);
        await _cache.SetAsync(key, MarkerBytes(), new DistributedCacheEntryOptions(), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> IsUserRevokedAsync(string userId, CancellationToken cancellationToken = default)
    {
        ValidateId(userId, nameof(userId));
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildUserIdKey(userId);
        var value = await _cache.GetAsync(key, cancellationToken).ConfigureAwait(false);
        return value != null;
    }

    /// <inheritdoc />
    public Task UnrevokeUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        ValidateId(userId, nameof(userId));
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildUserIdKey(userId);
        return _cache.RemoveAsync(key, cancellationToken);
    }

    /// <inheritdoc />
    public Task CleanupExpiredEntriesAsync(CancellationToken cancellationToken = default)
    {
        // Even though distributed-cache cleanup is a no-op, callers must not
        // observe success after requesting cancellation.
        cancellationToken.ThrowIfCancellationRequested();

        // Distributed caches handle expiration internally; no-op.
        return Task.CompletedTask;
    }

    private static byte[] MarkerBytes()
    {
        return System.Text.Encoding.UTF8.GetBytes("1");
    }

    private string BuildJtiKey(string jti)
    {
        return $"{_keyPrefix}:jti:{jti}";
    }

    private string BuildKeyIdKey(string keyId)
    {
        return $"{_keyPrefix}:kid:{keyId}";
    }

    private string BuildUserIdKey(string userId)
    {
        return $"{_keyPrefix}:sub:{userId}";
    }

    private static void ValidateId(string value, string paramName)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{paramName} cannot be empty or whitespace", paramName);
        }
    }
}
