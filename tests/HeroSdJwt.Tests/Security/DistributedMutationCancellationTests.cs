using HeroSdJwt.AspNetCore.Verification.ReplayProtection;
using HeroSdJwt.AspNetCore.Verification.Revocation;
using Microsoft.Extensions.Caching.Distributed;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A distributed backend may commit a mutation, ignore cancellation and return
/// normally. The adapter must not report successful completion to a caller
/// whose request was canceled while the backend was running.
/// </summary>
public sealed class DistributedMutationCancellationTests
{
    [Theory]
    [InlineData("RevokeJti")]
    [InlineData("RevokeKey")]
    [InlineData("UnrevokeKey")]
    [InlineData("RevokeUser")]
    [InlineData("UnrevokeUser")]
    public async Task Should_PropagateLateCancellation_AfterRevocationMutation(string operation)
    {
        using var cancellation = new CancellationTokenSource();
        var backend = new IgnoringCancellationCache(cancellation);
        var store = new DistributedRevocationStore(backend);

        Task Execute()
        {
            return operation switch
            {
                "RevokeJti" => store.RevokeJtiAsync("jti", DateTimeOffset.UtcNow.AddMinutes(10), cancellation.Token),
                "RevokeKey" => store.RevokeKeyAsync("kid", cancellation.Token),
                "UnrevokeKey" => store.UnrevokeKeyAsync("kid", cancellation.Token),
                "RevokeUser" => store.RevokeUserAsync("subject", cancellation.Token),
                "UnrevokeUser" => store.UnrevokeUserAsync("subject", cancellation.Token),
                _ => throw new ArgumentOutOfRangeException(nameof(operation))
            };
        }

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(Execute);
        Assert.Equal(1, backend.MutationCalls);
    }

    [Fact]
    public async Task Should_PropagateLateCancellation_AfterReplayMarkerRemoval()
    {
        using var cancellation = new CancellationTokenSource();
        var backend = new IgnoringCancellationCache(cancellation);
        var cache = new DistributedJtiCache(backend);

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            cache.RemoveAsync("issuer", "jti", cancellation.Token));
        Assert.Equal(1, backend.MutationCalls);
    }

    // Simulates a backend that completes the requested write/remove but ignores
    // cancellation. This does not assert that a committed mutation can be undone.
    private sealed class IgnoringCancellationCache(CancellationTokenSource cancellation)
        : IAtomicDistributedCache, IAtomicRevocationCache
    {
        public int MutationCalls { get; private set; }

        private Task CompleteMutation()
        {
            MutationCalls++;
            cancellation.Cancel();
            return Task.CompletedTask;
        }

        public Task SetOrExtendAsync(string key, byte[] value, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default) => CompleteMutation();

        public Task<bool> TryAddAsync(string key, byte[] value, TimeSpan ttl,
            CancellationToken cancellationToken = default) => Task.FromResult(true);

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) =>
            Task.FromResult<byte[]?>(null);

        public byte[]? Get(string key) => null;

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) { }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options,
            CancellationToken token = default) => CompleteMutation();

        public void Refresh(string key) { }

        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;

        public void Remove(string key) { }

        public Task RemoveAsync(string key, CancellationToken token = default) => CompleteMutation();
    }
}
