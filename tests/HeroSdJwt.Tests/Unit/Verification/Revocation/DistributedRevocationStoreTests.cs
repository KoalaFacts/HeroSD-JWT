using HeroSdJwt.AspNetCore.Verification.Revocation;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace HeroSdJwt.Tests.Unit.Verification.Revocation;

public class DistributedRevocationStoreTests : IDisposable
{
    private readonly IDistributedCache _cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    [Fact]
    public async Task RevokeJtiAsync_SetsFlag_AndExpires()
    {
        var backend = new AtomicRevocationCacheFixture();
        var store = new DistributedRevocationStore(backend);
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(1);

        await store.RevokeJtiAsync("jti-1", expiresAt, TestContext.Current.CancellationToken);

        Assert.True(await store.IsJtiRevokedAsync("jti-1", TestContext.Current.CancellationToken));

        backend.Advance(TimeSpan.FromMinutes(2));

        Assert.False(await store.IsJtiRevokedAsync("jti-1", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RevokeJtiAsync_OrdinaryDistributedCache_FailsClosedBeforeWriting()
    {
        var store = new DistributedRevocationStore(_cache);

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            store.RevokeJtiAsync("unsafe-backend", DateTimeOffset.UtcNow.AddHours(1), TestContext.Current.CancellationToken));

        Assert.False(await store.IsJtiRevokedAsync("unsafe-backend", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RevokeJtiAsync_ShorterRenewalCannotShortenAnExistingRevocation()
    {
        var backend = new AtomicRevocationCacheFixture();
        var firstNode = new DistributedRevocationStore(backend);
        var secondNode = new DistributedRevocationStore(backend);
        var now = DateTimeOffset.UtcNow;
        var token = TestContext.Current.CancellationToken;

        await firstNode.RevokeJtiAsync("same-jti", now.AddHours(1), token);
        await secondNode.RevokeJtiAsync("same-jti", now.AddMinutes(1), token);

        backend.Advance(TimeSpan.FromMinutes(2));
        Assert.True(await firstNode.IsJtiRevokedAsync("same-jti", token));

        backend.Advance(TimeSpan.FromHours(2));
        Assert.False(await secondNode.IsJtiRevokedAsync("same-jti", token));
    }

    [Fact]
    public async Task RevokeJtiAsync_ConcurrentRenewalsPreserveLongestExpiration()
    {
        var backend = new AtomicRevocationCacheFixture();
        var now = DateTimeOffset.UtcNow;
        var token = TestContext.Current.CancellationToken;
        var attempts = Enumerable.Range(0, 64).Select(i => Task.Run(async () =>
        {
            var store = new DistributedRevocationStore(backend);
            var expires = now.AddMinutes(i % 3 == 0 ? 60 : 1);
            await store.RevokeJtiAsync("parallel-jti", expires, token);
        }, token));
        await Task.WhenAll(attempts);

        backend.Advance(TimeSpan.FromMinutes(2));
        Assert.True(await new DistributedRevocationStore(backend).IsJtiRevokedAsync("parallel-jti", token));
    }

    [Fact]
    public async Task RevokeJtiAsync_ExistingPermanentMarkerMustRemainPermanent()
    {
        var backend = new AtomicRevocationCacheFixture();
        var store = new DistributedRevocationStore(backend);
        var token = TestContext.Current.CancellationToken;

        // Simulate a permanent marker written before the atomic renewal upgrade.
        // It must not become expiring when a second writer revokes the same JTI.
        backend.Set("sdjwt:revocation:jti:permanent", [1], new DistributedCacheEntryOptions());
        await store.RevokeJtiAsync("permanent", DateTimeOffset.UtcNow.AddMinutes(1), token);

        backend.Advance(TimeSpan.FromMinutes(2));
        Assert.True(await store.IsJtiRevokedAsync("permanent", token));
    }

    [Fact]
    public async Task RevokeJtiAsync_BackendFailureIsPropagatedWithoutAdmission()
    {
        var backend = new AtomicRevocationCacheFixture { FailAtomicWrites = true };
        var store = new DistributedRevocationStore(backend);

        await Assert.ThrowsAsync<IOException>(() =>
            store.RevokeJtiAsync("backend-error", DateTimeOffset.UtcNow.AddHours(1), TestContext.Current.CancellationToken));

        Assert.False(await store.IsJtiRevokedAsync("backend-error", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RevokeKeyAsync_SetsFlag()
    {
        var store = new DistributedRevocationStore(_cache);
        await store.RevokeKeyAsync("kid-1", TestContext.Current.CancellationToken);

        Assert.True(await store.IsKeyRevokedAsync("kid-1", TestContext.Current.CancellationToken));

        await store.UnrevokeKeyAsync("kid-1", TestContext.Current.CancellationToken);
        Assert.False(await store.IsKeyRevokedAsync("kid-1", TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task KeyRevocationOperations_RejectIdsVerifierCannotAccept(int invalidCase)
    {
        var keyId = invalidCase switch
        {
            0 => "kid\nforged-log-line",
            1 => "kid-\u00e9",
            _ => new string('k', 257)
        };
        var store = new DistributedRevocationStore(_cache);
        var token = TestContext.Current.CancellationToken;

        await Assert.ThrowsAsync<ArgumentException>(() => store.RevokeKeyAsync(keyId, token));
        Assert.Null(await _cache.GetAsync($"sdjwt:revocation:kid:{keyId}", token));

        await Assert.ThrowsAsync<ArgumentException>(() => store.IsKeyRevokedAsync(keyId, token));
        await Assert.ThrowsAsync<ArgumentException>(() => store.UnrevokeKeyAsync(keyId, token));
    }

    [Fact]
    public async Task RevokeUserAsync_SetsFlag()
    {
        var store = new DistributedRevocationStore(_cache);
        await store.RevokeUserAsync("user-1", TestContext.Current.CancellationToken);

        Assert.True(await store.IsUserRevokedAsync("user-1", TestContext.Current.CancellationToken));

        await store.UnrevokeUserAsync("user-1", TestContext.Current.CancellationToken);
        Assert.False(await store.IsUserRevokedAsync("user-1", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CleanupExpiredEntriesAsync_PreCanceledToken_ThrowsOperationCanceledException()
    {
        var store = new DistributedRevocationStore(_cache);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        _ = await Assert.ThrowsAsync<OperationCanceledException>(() =>
            store.CleanupExpiredEntriesAsync(cancellation.Token));
    }

    [Fact]
    public async Task CleanupExpiredEntriesAsync_ActiveToken_PreservesPermanentKeyRevocation()
    {
        var store = new DistributedRevocationStore(_cache);
        var token = TestContext.Current.CancellationToken;

        await store.RevokeKeyAsync("cleanup-safety-key", token);
        await store.CleanupExpiredEntriesAsync(token);

        Assert.True(await store.IsKeyRevokedAsync("cleanup-safety-key", token));
    }

    // Single-process contract fixture only. Its lock models an atomic backend
    // operation, not an actual Redis/SQL cross-instance implementation.
    private sealed class AtomicRevocationCacheFixture : IAtomicRevocationCache
    {
#if NET9_0_OR_GREATER
        private readonly Lock _sync = new();
#else
        private readonly object _sync = new();
#endif
        private readonly Dictionary<string, (byte[] Value, DateTimeOffset? Expires)> _entries = [];
        private DateTimeOffset _now = DateTimeOffset.UtcNow;

        public bool FailAtomicWrites { get; init; }

        public void Advance(TimeSpan time)
        {
            lock (_sync)
            {
                _now += time;
            }
        }

        public Task SetOrExtendAsync(string key, byte[] value, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (FailAtomicWrites)
            {
                throw new IOException("Atomic revocation backend unavailable");
            }

            lock (_sync)
            {
                if (expiresAt > _now &&
                    (!_entries.TryGetValue(key, out var existing) ||
                     (existing.Expires.HasValue && (existing.Expires.Value <= _now || existing.Expires.Value < expiresAt))))
                {
                    _entries[key] = (value, expiresAt);
                }
            }

            return Task.CompletedTask;
        }

        public byte[]? Get(string key)
        {
            lock (_sync)
            {
                return _entries.TryGetValue(key, out var entry) &&
                    (!entry.Expires.HasValue || entry.Expires.Value > _now) ? entry.Value : null;
            }
        }

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            return Task.FromResult(Get(key));
        }

        // The normal Set path deliberately retains overwrite semantics, so these
        // regression tests would expose the old get/set-style renewal behavior.
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            lock (_sync)
            {
                DateTimeOffset? expires = options.AbsoluteExpirationRelativeToNow.HasValue
                    ? _now + options.AbsoluteExpirationRelativeToNow.Value
                    : options.AbsoluteExpiration;
                _entries[key] = (value, expires);
            }
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            Set(key, value, options);
            return Task.CompletedTask;
        }

        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public void Remove(string key)
        {
            lock (_sync)
            {
                _entries.Remove(key);
            }
        }

        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            Remove(key);
            return Task.CompletedTask;
        }
    }

    public void Dispose()
    {
        (_cache as IDisposable)?.Dispose();
    }
}
