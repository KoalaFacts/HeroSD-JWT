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

        var ttl = expiresAt - DateTimeOffset.UtcNow;
        if (ttl <= TimeSpan.Zero)
        {
            // Already expired; nothing to store.
            return;
        }

        var key = BuildJtiKey(jti);
        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = ttl
        };
        await _cache.SetAsync(key, MarkerBytes(), options, cancellationToken).ConfigureAwait(false);
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
        ValidateId(keyId, nameof(keyId));
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildKeyIdKey(keyId);
        await _cache.SetAsync(key, MarkerBytes(), new DistributedCacheEntryOptions(), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> IsKeyRevokedAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ValidateId(keyId, nameof(keyId));
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildKeyIdKey(keyId);
        var value = await _cache.GetAsync(key, cancellationToken).ConfigureAwait(false);
        return value != null;
    }

    /// <inheritdoc />
    public Task UnrevokeKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ValidateId(keyId, nameof(keyId));
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
