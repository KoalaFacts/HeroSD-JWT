using HeroSdJwt.Verification.ReplayProtection;
using Microsoft.Extensions.Caching.Distributed;

namespace HeroSdJwt.AspNetCore.Verification.ReplayProtection;

/// <summary>
/// Distributed implementation of <see cref="IJtiCache"/> using <see cref="IDistributedCache"/>.
/// Intended for multi-node deployments; atomicity depends on the underlying cache provider.
/// </summary>
public sealed class DistributedJtiCache(IDistributedCache cache, string keyPrefix = "sdjwt:jti") : IJtiCache
{
    private readonly IDistributedCache _cache = cache ?? throw new ArgumentNullException(nameof(cache));
    private readonly string _keyPrefix = string.IsNullOrWhiteSpace(keyPrefix) ? "sdjwt:jti" : keyPrefix.Trim();

    /// <inheritdoc />
    public async Task<bool> TryAddAsync(
        string issuer,
        string jti,
        TimeSpan ttl,
        CancellationToken cancellationToken = default)
    {
        ValidateParameters(issuer, jti, ttl);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildKey(issuer, jti);

        // Check for existing entry
        var existing = await _cache.GetAsync(key, cancellationToken).ConfigureAwait(false);
        if (existing != null)
        {
            return false;
        }

        // Store marker with TTL
        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = ttl
        };

        await _cache.SetAsync(key, System.Text.Encoding.UTF8.GetBytes("1"), options, cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> ExistsAsync(
        string issuer,
        string jti,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(jti);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildKey(issuer, jti);
        var value = await _cache.GetAsync(key, cancellationToken).ConfigureAwait(false);
        return value != null;
    }

    /// <inheritdoc />
    public Task RemoveAsync(
        string issuer,
        string jti,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(jti);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildKey(issuer, jti);
        return _cache.RemoveAsync(key, cancellationToken);
    }

    private string BuildKey(string issuer, string jti)
    {
        return $"{_keyPrefix}:{issuer}:{jti}";
    }

    private static void ValidateParameters(string issuer, string jti, TimeSpan ttl)
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

        if (ttl <= TimeSpan.Zero)
        {
            throw new ArgumentException("TTL must be greater than zero", nameof(ttl));
        }
    }
}
