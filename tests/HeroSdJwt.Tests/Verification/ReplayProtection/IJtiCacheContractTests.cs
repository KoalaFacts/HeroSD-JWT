using HeroSdJwt.Verification.ReplayProtection;

namespace HeroSdJwt.Tests.Verification.ReplayProtection;

/// <summary>
/// Abstract base class for testing IJtiCache implementations.
/// Provides contract tests that all implementations must pass.
/// Concrete test classes should inherit from this and provide the cache instance via CreateCache().
/// </summary>
public abstract class IJtiCacheContractTests : IAsyncLifetime
{
    protected abstract IJtiCache CreateCache();
    protected IJtiCache? Cache { get; private set; }

    public virtual ValueTask InitializeAsync()
    {
        Cache = CreateCache();
        return ValueTask.CompletedTask;
    }

    public virtual ValueTask DisposeAsync()
    {
        if (Cache is IDisposable disposable)
        {
            disposable.Dispose();
        }
        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task TryAddAsync_FirstAdd_ReturnsTrue()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var ttl = TimeSpan.FromHours(1);

        // Act
        var result = await Cache!.TryAddAsync(issuer, jti, ttl, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task TryAddAsync_SecondAdd_ReturnsFalse()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var ttl = TimeSpan.FromHours(1);

        await Cache!.TryAddAsync(issuer, jti, ttl, TestContext.Current.CancellationToken);

        // Act - Try to add same jti again
        var result = await Cache.TryAddAsync(issuer, jti, ttl, TestContext.Current.CancellationToken);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task TryAddAsync_DifferentIssuers_BothSucceed()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();
        var issuer1 = "https://issuer1.example";
        var issuer2 = "https://issuer2.example";
        var ttl = TimeSpan.FromHours(1);

        // Act
        var result1 = await Cache!.TryAddAsync(issuer1, jti, ttl, TestContext.Current.CancellationToken);
        var result2 = await Cache.TryAddAsync(issuer2, jti, ttl, TestContext.Current.CancellationToken);

        // Assert - Same jti, different issuers should both succeed
        Assert.True(result1);
        Assert.True(result2);
    }

    [Fact]
    public async Task TryAddAsync_NullIssuer_ThrowsArgumentNullException()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();
        var ttl = TimeSpan.FromHours(1);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Cache!.TryAddAsync(null!, jti, ttl, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_NullJti_ThrowsArgumentNullException()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var ttl = TimeSpan.FromHours(1);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Cache!.TryAddAsync(issuer, null!, ttl, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_EmptyIssuer_ThrowsArgumentException()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();
        var ttl = TimeSpan.FromHours(1);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Cache!.TryAddAsync(string.Empty, jti, ttl, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_EmptyJti_ThrowsArgumentException()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var ttl = TimeSpan.FromHours(1);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Cache!.TryAddAsync(issuer, string.Empty, ttl, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_ZeroTtl_ThrowsArgumentException()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Cache!.TryAddAsync(issuer, jti, TimeSpan.Zero, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_NegativeTtl_ThrowsArgumentException()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Cache!.TryAddAsync(issuer, jti, TimeSpan.FromSeconds(-1), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ExistsAsync_AfterAdd_ReturnsTrue()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var ttl = TimeSpan.FromHours(1);

        await Cache!.TryAddAsync(issuer, jti, ttl, TestContext.Current.CancellationToken);

        // Act
        var exists = await Cache.ExistsAsync(issuer, jti, TestContext.Current.CancellationToken);

        // Assert
        Assert.True(exists);
    }

    [Fact]
    public async Task ExistsAsync_BeforeAdd_ReturnsFalse()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();

        // Act
        var exists = await Cache!.ExistsAsync(issuer, jti, TestContext.Current.CancellationToken);

        // Assert
        Assert.False(exists);
    }

    [Fact]
    public async Task ExistsAsync_AfterRemove_ReturnsFalse()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var ttl = TimeSpan.FromHours(1);

        await Cache!.TryAddAsync(issuer, jti, ttl, TestContext.Current.CancellationToken);
        await Cache.RemoveAsync(issuer, jti, TestContext.Current.CancellationToken);

        // Act
        var exists = await Cache.ExistsAsync(issuer, jti, TestContext.Current.CancellationToken);

        // Assert
        Assert.False(exists);
    }

    [Fact]
    public async Task RemoveAsync_NonExistentEntry_DoesNotThrow()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();

        // Act & Assert - Should be idempotent, no exception
        await Cache!.RemoveAsync(issuer, jti, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task RemoveAsync_ExistingEntry_RemovesSuccessfully()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var ttl = TimeSpan.FromHours(1);

        await Cache!.TryAddAsync(issuer, jti, ttl, TestContext.Current.CancellationToken);

        // Act
        await Cache.RemoveAsync(issuer, jti, TestContext.Current.CancellationToken);

        // Assert - Can add again after removal
        var canAdd = await Cache.TryAddAsync(issuer, jti, ttl, TestContext.Current.CancellationToken);
        Assert.True(canAdd);
    }

    [Fact]
    public async Task TryAddAsync_ConcurrentSameJti_ExactlyOneSucceeds()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var ttl = TimeSpan.FromHours(1);
        var concurrentCount = 100;

        // Act - Add same jti from 100 threads concurrently
        var tasks = Enumerable.Range(0, concurrentCount)
            .Select(_ => Task.Run(() => Cache!.TryAddAsync(issuer, jti, ttl, TestContext.Current.CancellationToken), TestContext.Current.CancellationToken))
            .ToList();

        var results = await Task.WhenAll(tasks);
        var successCount = results.Count(r => r);

        // Assert - Exactly ONE should succeed (atomic operation)
        Assert.Equal(1, successCount);
        Assert.Equal(concurrentCount - 1, results.Count(r => !r)); // Rest should fail
    }
}
