using HeroSdJwt.Verification.ReplayProtection;
using Microsoft.Extensions.Caching.Distributed;

namespace HeroSdJwt.AspNetCore.Verification.ReplayProtection;

/// <summary>
/// Distributed replay protection backed by an <see cref="IAtomicDistributedCache"/>.
/// Ordinary distributed caches are rejected because read-then-write admission is not atomic.
/// </summary>
public sealed class DistributedJtiCache : IJtiCache
{
    private readonly IAtomicDistributedCache _cache;
    private readonly string _keyPrefix;

    /// <summary>
    /// Creates an adapter that requires backend-atomic create-if-absent with expiration.
    /// </summary>
    /// <param name="cache">A cache implementing <see cref="IAtomicDistributedCache"/>.</param>
    /// <param name="keyPrefix">The shared replay-marker namespace.</param>
    /// <exception cref="ArgumentNullException">The cache is null.</exception>
    /// <exception cref="NotSupportedException">The cache does not expose the atomic capability.</exception>
    public DistributedJtiCache(IDistributedCache cache, string keyPrefix = "sdjwt:jti")
    {
        ArgumentNullException.ThrowIfNull(cache);
        _cache = cache as IAtomicDistributedCache
            ?? throw new NotSupportedException(
                "Distributed replay protection requires IAtomicDistributedCache with backend-atomic " +
                "create-if-absent and TTL. Register an atomic provider or a direct IJtiCache implementation.");
        _keyPrefix = string.IsNullOrWhiteSpace(keyPrefix) ? "sdjwt:jti" : keyPrefix.Trim();
    }

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

        return await _cache.TryAddAsync(key, [1], ttl, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> ExistsAsync(
        string issuer,
        string jti,
        CancellationToken cancellationToken = default)
    {
        ValidateKeyParts(issuer, jti);
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
        ValidateKeyParts(issuer, jti);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildKey(issuer, jti);
        return _cache.RemoveAsync(key, cancellationToken);
    }

    private string BuildKey(string issuer, string jti)
    {
        // Length-prefix every component, including the namespace, so embedded colons
        // cannot alias a different (prefix, issuer, jti) tuple. Keep lengths culture-independent.
        return FormattableString.Invariant($"sdjwt:jti:v2:{_keyPrefix.Length}:{_keyPrefix}:{issuer.Length}:{issuer}:{jti.Length}:{jti}");
    }

    private static void ValidateParameters(string issuer, string jti, TimeSpan ttl)
    {
        ValidateKeyParts(issuer, jti);

        if (ttl <= TimeSpan.Zero)
        {
            throw new ArgumentException("TTL must be greater than zero", nameof(ttl));
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
}
