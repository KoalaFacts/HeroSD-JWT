using System.Collections.Concurrent;
namespace HeroSdJwt.Verification.Revocation;

/// <summary>
/// In-memory implementation of <see cref="IRevocationStore"/> for single-process scenarios.
/// Uses concurrent dictionaries for thread-safe operations and automatic cleanup timer.
/// </summary>
/// <remarks>
/// <para>
/// **Performance Characteristics**:
/// - Lookups: O(1) average case via hash table
/// - Memory: ~80 bytes per revoked JTI entry
/// - Throughput: 10,000+ lookups/sec per core
/// </para>
/// <para>
/// **Automatic Cleanup**: Expired JTI entries are removed every 5 minutes via background timer.
/// </para>
/// <para>
/// **Thread Safety**: All operations are thread-safe using ConcurrentDictionary.
/// </para>
/// <para>
/// **Scalability Limits**: Suitable for single-instance deployments with &lt;100k active revocations.
/// For distributed scenarios, implement custom <see cref="IRevocationStore"/> with Redis/SQL.
/// </para>
/// </remarks>
public sealed class InMemoryRevocationStore : IRevocationStore, IDisposable
{
    // Storage for revoked JTIs with expiration times
    private readonly ConcurrentDictionary<string, DateTimeOffset> _revokedJtis = new();

    // Storage for revoked key IDs (no expiration, manual cleanup only)
    private readonly ConcurrentDictionary<string, DateTimeOffset> _revokedKeys = new();

    // Storage for revoked user IDs (no expiration, manual cleanup only)
    private readonly ConcurrentDictionary<string, DateTimeOffset> _revokedUsers = new();

    // Background cleanup loop for automatic cleanup of expired JTI entries
    private readonly CancellationTokenSource _cleanupCts = new();
    private readonly Task _cleanupTask;
    private int _disposed;

    // Cleanup interval (default: 5 minutes)
    private static readonly TimeSpan _cleanupInterval = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryRevocationStore"/> class.
    /// Starts the background cleanup timer.
    /// </summary>
    public InMemoryRevocationStore()
    {
        _cleanupTask = RunCleanupLoopAsync(_cleanupCts.Token);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // JTI Revocation Implementation
    // ═══════════════════════════════════════════════════════════════════════

    /// <inheritdoc />
    public Task RevokeJtiAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jti);

        if (string.IsNullOrWhiteSpace(jti))
        {
            throw new ArgumentException("JTI cannot be empty or whitespace", nameof(jti));
        }

        cancellationToken.ThrowIfCancellationRequested();

        // A repeated revocation must never shorten an existing live marker.
        // Otherwise an earlier expiry supplied by a concurrent caller could
        // cause cleanup to re-admit a credential that is still revoked.
        _ = _revokedJtis.AddOrUpdate(jti, expiresAt,
            (_, previousExpiry) => previousExpiry >= expiresAt ? previousExpiry : expiresAt);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> IsJtiRevokedAsync(string jti, CancellationToken cancellationToken = default)
    {
        ValidateId(jti, nameof(jti));
        cancellationToken.ThrowIfCancellationRequested();

        // Expiration is effective at read time, not only when the five-minute
        // background cleanup removes the dictionary entry. Match the semantics
        // of distributed stores that expire revocation markers on read.
        var now = DateTimeOffset.UtcNow;
        return Task.FromResult(_revokedJtis.TryGetValue(jti, out var expiresAt) && expiresAt > now);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Key ID Revocation Implementation
    // ═══════════════════════════════════════════════════════════════════════

    /// <inheritdoc />
    public Task RevokeKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyId);

        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new ArgumentException("Key ID cannot be empty or whitespace", nameof(keyId));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var revokedAt = DateTimeOffset.UtcNow;
        _ = _revokedKeys.AddOrUpdate(keyId, revokedAt, (_, __) => revokedAt);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> IsKeyRevokedAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ValidateId(keyId, nameof(keyId));
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(_revokedKeys.ContainsKey(keyId));
    }

    /// <inheritdoc />
    public Task UnrevokeKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ValidateId(keyId, nameof(keyId));
        cancellationToken.ThrowIfCancellationRequested();

        // Idempotent: TryRemove returns false if key doesn't exist, which is fine
        _ = _revokedKeys.TryRemove(keyId, out _);

        return Task.CompletedTask;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // User ID Revocation Implementation
    // ═══════════════════════════════════════════════════════════════════════

    /// <inheritdoc />
    public Task RevokeUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);

        if (string.IsNullOrWhiteSpace(userId))
        {
            throw new ArgumentException("User ID cannot be empty or whitespace", nameof(userId));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var revokedAt = DateTimeOffset.UtcNow;
        _ = _revokedUsers.AddOrUpdate(userId, revokedAt, (_, __) => revokedAt);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> IsUserRevokedAsync(string userId, CancellationToken cancellationToken = default)
    {
        ValidateId(userId, nameof(userId));
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(_revokedUsers.ContainsKey(userId));
    }

    /// <inheritdoc />
    public Task UnrevokeUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        ValidateId(userId, nameof(userId));
        cancellationToken.ThrowIfCancellationRequested();

        // Idempotent: TryRemove returns false if user doesn't exist, which is fine
        _ = _revokedUsers.TryRemove(userId, out _);

        return Task.CompletedTask;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup Implementation
    // ═══════════════════════════════════════════════════════════════════════

    /// <inheritdoc />
    public Task CleanupExpiredEntriesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var now = DateTimeOffset.UtcNow;

        // Find all expired JTI entries
        var expiredJtis = _revokedJtis
            .Where(kvp => kvp.Value <= now)
            .ToList();

        // A revocation may be renewed after the snapshot is taken. Remove only
        // when the key AND its observed expiry still match, so cleanup cannot
        // discard a replacement revocation from another request.
        var conditionalRemover = (ICollection<KeyValuePair<string, DateTimeOffset>>)_revokedJtis;
        foreach (var expired in expiredJtis)
        {
            _ = conditionalRemover.Remove(expired);
        }

        return Task.CompletedTask;
    }

    private static void ValidateId(string value, string paramName)
    {
        ArgumentNullException.ThrowIfNull(value, paramName);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{paramName} cannot be empty or whitespace", paramName);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // IDisposable Implementation
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Disposes the background cleanup timer and releases resources.
    /// </summary>
    public void Dispose()
    {
        // A service container and an owning caller may both dispose the same
        // instance. Only one caller may cancel and dispose the shared CTS.
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _cleanupCts.Cancel();
        try
        {
            // Dispose is synchronous; wait for the background loop to finish before releasing resources.
            _cleanupTask.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            // expected during disposal
        }
        _cleanupCts.Dispose();
    }

    private async Task RunCleanupLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var timer = new PeriodicTimer(_cleanupInterval);
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                await CleanupExpiredEntriesAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // graceful shutdown
        }
    }
}
