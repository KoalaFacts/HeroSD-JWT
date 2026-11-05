using HeroSdJwt.AspNetCore.Verification.Revocation;
using Microsoft.Extensions.Caching.Distributed;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A distributed cache may complete a revocation read normally despite caller
/// cancellation. The adapter must not expose an allow decision from that read.
/// </summary>
public sealed class DistributedRevocationReadCancellationTests
{
    [Theory]
    [InlineData("jti", false)]
    [InlineData("jti", true)]
    [InlineData("key", false)]
    [InlineData("key", true)]
    [InlineData("user", false)]
    [InlineData("user", true)]
    public async Task Should_PropagateCallerCancellation_WhenBackendReturnsNormally(
        string kind, bool markerExists)
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var backend = new CancellationIgnoringCache(caller, markerExists);
        var store = new DistributedRevocationStore(backend);

        Task<bool> lookup = kind switch
        {
            "jti" => store.IsJtiRevokedAsync("test-jti", caller.Token),
            "key" => store.IsKeyRevokedAsync("test-key", caller.Token),
            "user" => store.IsUserRevokedAsync("test-user", caller.Token),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };

        // The backend returns either a missing marker or a present marker after
        // canceling the caller, rather than throwing on the cancellation token.
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lookup);
        Assert.Equal(1, backend.Reads);
    }

    private sealed class CancellationIgnoringCache(CancellationTokenSource caller, bool markerExists)
        : IDistributedCache
    {
        public int Reads { get; private set; }

        public byte[]? Get(string key) => throw new NotSupportedException();

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            Reads++;
            caller.Cancel();
            return Task.FromResult<byte[]?>(markerExists ? [1] : null);
        }

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
