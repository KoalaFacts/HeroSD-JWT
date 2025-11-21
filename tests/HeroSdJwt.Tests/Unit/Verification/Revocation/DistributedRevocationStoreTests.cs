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
        var store = new DistributedRevocationStore(_cache);
        var expiresAt = DateTimeOffset.UtcNow.AddMilliseconds(200);

        await store.RevokeJtiAsync("jti-1", expiresAt, TestContext.Current.CancellationToken);

        Assert.True(await store.IsJtiRevokedAsync("jti-1", TestContext.Current.CancellationToken));

        await Task.Delay(300, TestContext.Current.CancellationToken);

        Assert.False(await store.IsJtiRevokedAsync("jti-1", TestContext.Current.CancellationToken));
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

    [Fact]
    public async Task RevokeUserAsync_SetsFlag()
    {
        var store = new DistributedRevocationStore(_cache);
        await store.RevokeUserAsync("user-1", TestContext.Current.CancellationToken);

        Assert.True(await store.IsUserRevokedAsync("user-1", TestContext.Current.CancellationToken));

        await store.UnrevokeUserAsync("user-1", TestContext.Current.CancellationToken);
        Assert.False(await store.IsUserRevokedAsync("user-1", TestContext.Current.CancellationToken));
    }

    public void Dispose()
    {
        (_cache as IDisposable)?.Dispose();
    }
}
