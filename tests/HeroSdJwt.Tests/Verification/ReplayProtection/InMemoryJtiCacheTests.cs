using HeroSdJwt.Verification.ReplayProtection;

namespace HeroSdJwt.Tests.Verification.ReplayProtection;

/// <summary>
/// Tests for InMemoryJtiCache implementation.
/// Inherits contract tests and adds implementation-specific tests.
/// </summary>
public class InMemoryJtiCacheTests : IJtiCacheContractTests
{
    protected override IJtiCache CreateCache()
    {
        var options = new ReplayProtectionOptions
        {
            MaxCacheEntries = 10000,
            DefaultTtl = TimeSpan.FromHours(1),
            MaximumTtl = TimeSpan.FromHours(24)
        };
        return new InMemoryJtiCache(options);
    }

    [Fact]
    public async Task TryAddAsync_ExpirationAfterTtl_EntryRemoved()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var ttl = TimeSpan.FromMilliseconds(100); // Very short TTL for test

        _ = await Cache!.TryAddAsync(issuer, jti, ttl, TestContext.Current.CancellationToken);

        // Act - Wait for expiration
        await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);

        // Force cleanup (implementation detail - cache should have periodic cleanup)
        // For now, just verify that we CAN add again (TTL expired)
        var canAddAgain = await Cache.TryAddAsync(issuer, jti, TimeSpan.FromHours(1), TestContext.Current.CancellationToken);

        // Assert - Entry should be gone after expiration
        // Note: This may pass immediately if cleanup hasn't run yet
        // The important test is that eventually it's cleaned up
        Assert.True(canAddAgain);
    }

    [Fact]
    public async Task Should_RejectAdmissionWithoutEvictingLiveJtis_WhenAtCapacity()
    {
        var options = new ReplayProtectionOptions { MaxCacheEntries = 2 };
        using var cache = new InMemoryJtiCache(options);
        const string issuer = "https://issuer.example";
        var token = TestContext.Current.CancellationToken;

        Assert.True(await cache.TryAddAsync(issuer, "first", TimeSpan.FromHours(1), token));
        Assert.True(await cache.TryAddAsync(issuer, "second", TimeSpan.FromHours(1), token));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            cache.TryAddAsync(issuer, "third", TimeSpan.FromHours(1), token));

        Assert.Contains("capacity", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.True(await cache.ExistsAsync(issuer, "first", token));
        Assert.True(await cache.ExistsAsync(issuer, "second", token));
        Assert.False(await cache.ExistsAsync(issuer, "third", token));
        Assert.False(await cache.TryAddAsync(issuer, "first", TimeSpan.FromHours(1), token));
    }

    [Fact]
    public async Task Should_ReclaimOnlyExpiredMarkers_WhenCapacityIsFull()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 10, 24, 0, 0, 0, TimeSpan.Zero));
        var options = new ReplayProtectionOptions { MaxCacheEntries = 2 };
        using var cache = new InMemoryJtiCache(options, clock);
        const string issuer = "issuer";
        var token = TestContext.Current.CancellationToken;

        Assert.True(await cache.TryAddAsync(issuer, "long-lived", TimeSpan.FromHours(1), token));
        Assert.True(await cache.TryAddAsync(issuer, "short-lived", TimeSpan.FromMinutes(1), token));
        clock.Advance(TimeSpan.FromMinutes(2));

        Assert.True(await cache.TryAddAsync(issuer, "replacement", TimeSpan.FromMinutes(10), token));
        Assert.True(await cache.ExistsAsync(issuer, "long-lived", token));
        Assert.False(await cache.ExistsAsync(issuer, "short-lived", token));
        Assert.True(await cache.ExistsAsync(issuer, "replacement", token));
        Assert.False(await cache.TryAddAsync(issuer, "long-lived", TimeSpan.FromMinutes(1), token));
    }

    [Fact]
    public async Task Should_AdmitAtMostCapacity_WhenDistinctJtisRace()
    {
        const int capacity = 4;
        const int attempts = 32;
        var options = new ReplayProtectionOptions { MaxCacheEntries = capacity };
        using var cache = new InMemoryJtiCache(options);
        var token = TestContext.Current.CancellationToken;
        var tasks = Enumerable.Range(0, attempts).Select(i => Task.Run(async () =>
        {
            try
            {
                return await cache.TryAddAsync("issuer", $"concurrent-{i}", TimeSpan.FromHours(1), token);
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }, token));

        var admitted = await Task.WhenAll(tasks);
        Assert.Equal(capacity, admitted.Count(value => value));

        for (var i = 0; i < attempts; i++)
        {
            var jti = $"concurrent-{i}";
            Assert.Equal(admitted[i], await cache.ExistsAsync("issuer", jti, token));
            if (admitted[i])
            {
                Assert.False(await cache.TryAddAsync("issuer", jti, TimeSpan.FromHours(1), token));
            }
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public async Task Should_PreserveEveryLiveMarker_WhenReplaysAndNewcomersRaceAtCapacity(int capacity)
    {
        using var cache = new InMemoryJtiCache(new ReplayProtectionOptions { MaxCacheEntries = capacity });
        var token = TestContext.Current.CancellationToken;
        for (var i = 0; i < capacity; i++)
        {
            Assert.True(await cache.TryAddAsync("issuer", $"live-{i}", TimeSpan.FromHours(1), token));
        }

        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tasks = Enumerable.Range(0, 32).Select(i => Task.Run(async () =>
        {
            await start.Task.WaitAsync(token);
            Assert.False(await cache.TryAddAsync("issuer", $"live-{i % capacity}", TimeSpan.FromHours(1), token));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                cache.TryAddAsync("issuer", $"new-{i}", TimeSpan.FromHours(1), token));
            Assert.False(await cache.ExistsAsync("issuer", $"new-{i}", token));
        }, token)).ToArray();
        start.SetResult();
        await Task.WhenAll(tasks);

        for (var i = 0; i < capacity; i++)
        {
            Assert.True(await cache.ExistsAsync("issuer", $"live-{i}", token));
            Assert.False(await cache.TryAddAsync("issuer", $"live-{i}", TimeSpan.FromHours(1), token));
        }
    }

    [Fact]
    public async Task Should_NotReserveJti_WhenAdmissionIsCancelled()
    {
        using var cache = new InMemoryJtiCache(new ReplayProtectionOptions { MaxCacheEntries = 1 });
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            cache.TryAddAsync("issuer", "cancelled", TimeSpan.FromMinutes(1), cancellation.Token));

        Assert.False(await cache.ExistsAsync("issuer", "cancelled", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ConcurrentOperations_ThreadSafe()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var operationCount = 1000;

        // Act - Perform many concurrent operations
        var tasks = new List<Task>();
        for (int i = 0; i < operationCount; i++)
        {
            var jti = $"jti-{i}";
            tasks.Add(Task.Run(async () =>
            {
                _ = await Cache!.TryAddAsync(issuer, jti, TimeSpan.FromHours(1), TestContext.Current.CancellationToken);
                _ = await Cache.ExistsAsync(issuer, jti, TestContext.Current.CancellationToken);
            }, TestContext.Current.CancellationToken));
        }

        // Assert - Should complete without exceptions
        await Task.WhenAll(tasks);
        // If we got here, thread safety is maintained
        Assert.True(true);
    }

    [Fact]
    public async Task RemoveAsync_ImmediatelyAllowsReAdd()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();

        _ = await Cache!.TryAddAsync(issuer, jti, TimeSpan.FromHours(1), TestContext.Current.CancellationToken);
        await Cache.RemoveAsync(issuer, jti, TestContext.Current.CancellationToken);

        // Act
        var canAddAgain = await Cache.TryAddAsync(issuer, jti, TimeSpan.FromHours(1), TestContext.Current.CancellationToken);

        // Assert
        Assert.True(canAddAgain);
    }

    [Fact]
    public async Task Should_ReclaimExpiredMarkers_WithoutAllocatingProportionallyToExpiredCount()
    {
        // A full cache must reclaim expired entries under the admission lock.
        // A temporary array of 10,000 expired keys would allocate at least 80 KiB
        // on a 64-bit runner, amplifying memory pressure at capacity.
        const int capacity = 20_000;
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 10, 27, 0, 0, 0, TimeSpan.Zero));
        using var cache = new InMemoryJtiCache(new ReplayProtectionOptions { MaxCacheEntries = capacity }, clock);
        var token = TestContext.Current.CancellationToken;

        for (var i = 0; i < capacity; i++)
        {
            var ttl = i % 2 == 0 ? TimeSpan.FromMinutes(1) : TimeSpan.FromHours(1);
            Assert.True(await cache.TryAddAsync("issuer", $"marker-{i}", ttl, token));
        }

        clock.Advance(TimeSpan.FromMinutes(2));

        // Capture only the synchronous cleanup/admission path, not test setup
        // or asynchronous continuations; the cache returns a completed Task.
        var before = GC.GetAllocatedBytesForCurrentThread();
        var admission = cache.TryAddAsync("issuer", "replacement", TimeSpan.FromHours(1), token);
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(await admission);
        Assert.True(allocatedBytes < 32 * 1024,
            $"Cleanup allocated {allocatedBytes} bytes for expired markers.");
        Assert.True(await cache.ExistsAsync("issuer", "marker-1", token));
        Assert.False(await cache.ExistsAsync("issuer", "marker-0", token));
        Assert.True(await cache.ExistsAsync("issuer", "replacement", token));
    }

    private sealed class ManualTimeProvider(DateTimeOffset initialUtc) : TimeProvider
    {
        private DateTimeOffset _utcNow = initialUtc;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan elapsed) => _utcNow = _utcNow.Add(elapsed);
    }

}
