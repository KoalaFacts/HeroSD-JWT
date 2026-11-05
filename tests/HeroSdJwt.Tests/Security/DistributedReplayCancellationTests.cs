using HeroSdJwt.AspNetCore.Verification.ReplayProtection;
using Microsoft.Extensions.Caching.Distributed;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A backend may ignore cancellation and complete replay operations normally.
/// The adapter must not report an admission or a diagnostic read as successful
/// when its caller canceled before the backend returned.
/// </summary>
public sealed class DistributedReplayCancellationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_PropagateCallerCancellation_WhenReplayReadBackendReturnsNormally(bool markerExists)
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var backend = new CancellationIgnoringAtomicCache(caller, markerExists);
        var cache = new DistributedJtiCache(backend);

        var lookup = cache.ExistsAsync("issuer", "jti", caller.Token);

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lookup);
        Assert.Equal(1, backend.Reads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_PropagateCallerCancellation_WhenAtomicAdmissionBackendReturnsNormally(bool admitted)
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var backend = new CancellationIgnoringAtomicCache(caller, admitted);
        var cache = new DistributedJtiCache(backend);

        var admission = cache.TryAddAsync("issuer", "jti", TimeSpan.FromMinutes(1), caller.Token);

        // The backend can already have committed an admission; cancellation
        // must still reach the caller, without attempting to undo the marker.
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => admission);
        Assert.Equal(1, backend.Admissions);
    }

    private sealed class CancellationIgnoringAtomicCache(CancellationTokenSource caller, bool result)
        : IAtomicDistributedCache
    {
        public int Reads { get; private set; }
        public int Admissions { get; private set; }

        public Task<bool> TryAddAsync(string key, byte[] value, TimeSpan ttl,
            CancellationToken cancellationToken = default)
        {
            Admissions++;
            caller.Cancel();
            return Task.FromResult(result);
        }

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            Reads++;
            caller.Cancel();
            return Task.FromResult<byte[]?>(result ? [1] : null);
        }

        public byte[]? Get(string key) => throw new NotSupportedException();
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) =>
            throw new NotSupportedException();
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options,
            CancellationToken token = default) => throw new NotSupportedException();
        public void Refresh(string key) => throw new NotSupportedException();
        public Task RefreshAsync(string key, CancellationToken token = default) =>
            throw new NotSupportedException();
        public void Remove(string key) => throw new NotSupportedException();
        public Task RemoveAsync(string key, CancellationToken token = default) =>
            throw new NotSupportedException();
    }
}
