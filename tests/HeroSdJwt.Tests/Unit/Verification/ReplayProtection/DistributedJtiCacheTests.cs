using HeroSdJwt.Verification.ReplayProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace HeroSdJwt.Tests.Unit.Verification.ReplayProtection;

public class DistributedJtiCacheTests : IDisposable
{
    private readonly IDistributedCache _cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    [Fact]
    public async Task TryAddAsync_FirstCall_Succeeds()
    {
        var cache = new DistributedJtiCache(_cache);
        var ttl = TimeSpan.FromMinutes(1);

        var added = await cache.TryAddAsync("issuer", "jti-1", ttl, TestContext.Current.CancellationToken);

        Assert.True(added);
        Assert.True(await cache.ExistsAsync("issuer", "jti-1", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_SecondCall_Fails()
    {
        var cache = new DistributedJtiCache(_cache);
        var ttl = TimeSpan.FromMinutes(1);

        await cache.TryAddAsync("issuer", "jti-dup", ttl, TestContext.Current.CancellationToken);
        var second = await cache.TryAddAsync("issuer", "jti-dup", ttl, TestContext.Current.CancellationToken);

        Assert.False(second);
    }

    [Fact]
    public async Task ExistsAsync_ReturnsFalse_ForMissing()
    {
        var cache = new DistributedJtiCache(_cache);
        Assert.False(await cache.ExistsAsync("issuer", "missing", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RemoveAsync_RemovesKey()
    {
        var cache = new DistributedJtiCache(_cache);
        var ttl = TimeSpan.FromMinutes(1);

        await cache.TryAddAsync("issuer", "jti-remove", ttl, TestContext.Current.CancellationToken);
        await cache.RemoveAsync("issuer", "jti-remove", TestContext.Current.CancellationToken);

        Assert.False(await cache.ExistsAsync("issuer", "jti-remove", TestContext.Current.CancellationToken));
    }

    public void Dispose()
    {
        (_cache as IDisposable)?.Dispose();
    }
}
