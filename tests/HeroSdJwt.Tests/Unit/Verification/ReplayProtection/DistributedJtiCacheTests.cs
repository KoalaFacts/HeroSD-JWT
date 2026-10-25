using HeroSdJwt.AspNetCore.Verification.ReplayProtection;

namespace HeroSdJwt.Tests.Unit.Verification.ReplayProtection;

public class DistributedJtiCacheTests
{
    private readonly AtomicCacheFixture _cache = new();

    [Theory]
    [InlineData(null, "valid-jti", true)]
    [InlineData("", "valid-jti", false)]
    [InlineData(" \t ", "valid-jti", false)]
    [InlineData("valid-issuer", null, true)]
    [InlineData("valid-issuer", "", false)]
    [InlineData("valid-issuer", " \t ", false)]
    public async Task DiagnosticOperations_WithInvalidIdentity_RejectBeforeBackendAccess(
        string? issuer, string? jti, bool isNull)
    {
        var cache = new DistributedJtiCache(_cache);
        var token = TestContext.Current.CancellationToken;
        Task Exists() => cache.ExistsAsync(issuer!, jti!, token);
        Task Remove() => cache.RemoveAsync(issuer!, jti!, token);

        if (isNull)
        {
            _ = await Assert.ThrowsAsync<ArgumentNullException>(Exists);
            _ = await Assert.ThrowsAsync<ArgumentNullException>(Remove);
        }
        else
        {
            _ = await Assert.ThrowsAsync<ArgumentException>(Exists);
            _ = await Assert.ThrowsAsync<ArgumentException>(Remove);
        }
    }

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

        _ = await cache.TryAddAsync("issuer", "jti-dup", ttl, TestContext.Current.CancellationToken);
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

        _ = await cache.TryAddAsync("issuer", "jti-remove", ttl, TestContext.Current.CancellationToken);
        await cache.RemoveAsync("issuer", "jti-remove", TestContext.Current.CancellationToken);

        Assert.False(await cache.ExistsAsync("issuer", "jti-remove", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task IndependentAdapters_ConcurrentAdmission_HasExactlyOneWinner()
    {
        const int concurrency = 32;
        var backend = new AtomicCacheFixture(concurrency);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var attempts = Enumerable.Range(0, concurrency)
            .Select(_ => new DistributedJtiCache(backend)
                .TryAddAsync("issuer", "concurrent-jti", TimeSpan.FromMinutes(1), deadline.Token));

        var admitted = await Task.WhenAll(attempts);

        Assert.Equal(1, admitted.Count(result => result));
        Assert.True(await new DistributedJtiCache(backend).ExistsAsync("issuer", "concurrent-jti", deadline.Token));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(600)]
    public async Task DuplicateAdmission_PreservesOriginalTtl_AndAllowsAdmissionAtExpiry(int duplicateTtlSeconds)
    {
        var firstNode = new DistributedJtiCache(_cache);
        var secondNode = new DistributedJtiCache(_cache);
        var token = TestContext.Current.CancellationToken;
        Assert.True(await firstNode.TryAddAsync("issuer", "expiring", TimeSpan.FromSeconds(10), token));
        _cache.Advance(TimeSpan.FromSeconds(3));
        Assert.False(await secondNode.TryAddAsync("issuer", "expiring", TimeSpan.FromSeconds(duplicateTtlSeconds), token));
        _cache.Advance(TimeSpan.FromSeconds(6));
        Assert.True(await firstNode.ExistsAsync("issuer", "expiring", token));
        _cache.Advance(TimeSpan.FromSeconds(1));
        Assert.False(await firstNode.ExistsAsync("issuer", "expiring", token));
        Assert.True(await secondNode.TryAddAsync("issuer", "expiring", TimeSpan.FromSeconds(10), token));
    }

    [Fact]
    public async Task CancelledAdmission_DoesNotConsumeIdentifier()
    {
        var cache = new DistributedJtiCache(_cache);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cache.TryAddAsync("issuer", "cancelled", TimeSpan.FromMinutes(1), cancellation.Token));

        Assert.True(await cache.TryAddAsync("issuer", "cancelled", TimeSpan.FromMinutes(1), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CancellationDuringBackendOperation_IsPropagated()
    {
        var backend = new AtomicCacheFixture { WaitForCancellation = true };
        var cache = new DistributedJtiCache(backend);
        using var cancellation = new CancellationTokenSource();
        var pending = cache.TryAddAsync("issuer", "cancelled", TimeSpan.FromMinutes(1), cancellation.Token);
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        Assert.False(await cache.ExistsAsync("issuer", "cancelled", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task BackendFailure_IsPropagatedWithoutAdmission()
    {
        var backend = new AtomicCacheFixture { AdmissionFailure = new IOException("Backend unavailable") };
        var cache = new DistributedJtiCache(backend);

        await Assert.ThrowsAsync<IOException>(() => cache.TryAddAsync("issuer", "failure", TimeSpan.FromMinutes(1), TestContext.Current.CancellationToken));
        Assert.False(await cache.ExistsAsync("issuer", "failure", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task NamespaceAndIssuer_SeparateAdmissions()
    {
        var first = new DistributedJtiCache(_cache, "first");
        var second = new DistributedJtiCache(_cache, "second");
        var token = TestContext.Current.CancellationToken;
        Assert.True(await first.TryAddAsync("issuer", "same", TimeSpan.FromMinutes(1), token));
        Assert.True(await second.TryAddAsync("issuer", "same", TimeSpan.FromMinutes(1), token));
        Assert.True(await first.TryAddAsync("other-issuer", "same", TimeSpan.FromMinutes(1), token));
        Assert.False(await first.TryAddAsync("issuer", "same", TimeSpan.FromMinutes(1), token));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task NonPositiveTtl_IsRejectedWithoutAdmission(int seconds)
    {
        var cache = new DistributedJtiCache(_cache);
        await Assert.ThrowsAsync<ArgumentException>(() => cache.TryAddAsync("issuer", "invalid-ttl", TimeSpan.FromSeconds(seconds), TestContext.Current.CancellationToken));
        Assert.False(await cache.ExistsAsync("issuer", "invalid-ttl", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DelimitersInIssuerAndJti_DoNotAliasDistinctPairs()
    {
        var cache = new DistributedJtiCache(_cache);
        var token = TestContext.Current.CancellationToken;
        Assert.True(await cache.TryAddAsync("a:b", "c", TimeSpan.FromMinutes(1), token));
        Assert.True(await cache.TryAddAsync("a", "b:c", TimeSpan.FromMinutes(1), token));

        await cache.RemoveAsync("a:b", "c", token);

        Assert.False(await cache.ExistsAsync("a:b", "c", token));
        Assert.True(await cache.ExistsAsync("a", "b:c", token));
    }

    [Fact]
    public async Task DelimitersInPrefix_DoNotAliasDistinctNamespaces()
    {
        var first = new DistributedJtiCache(_cache, "a:b");
        var second = new DistributedJtiCache(_cache, "a");
        var token = TestContext.Current.CancellationToken;
        Assert.True(await first.TryAddAsync("c", "d", TimeSpan.FromMinutes(1), token));
        Assert.True(await second.TryAddAsync("b:c", "d", TimeSpan.FromMinutes(1), token));

        await first.RemoveAsync("c", "d", token);

        Assert.False(await first.ExistsAsync("c", "d", token));
        Assert.True(await second.ExistsAsync("b:c", "d", token));
    }

}
