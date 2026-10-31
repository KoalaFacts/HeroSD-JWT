using HeroSdJwt.Verification.Revocation;

namespace HeroSdJwt.Tests.Unit.Verification.Revocation;

public class InMemoryRevocationStoreTests
{
    private readonly CancellationToken _ct = TestContext.Current.CancellationToken;

    // ═══════════════════════════════════════════════════════════════════════
    // JTI Revocation Tests
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task RevokeJtiAsync_WithValidJti_StoresEntry()
    {
        var store = new InMemoryRevocationStore();
        var jti = "test-jti-123";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        await store.RevokeJtiAsync(jti, expiresAt, _ct);

        var isRevoked = await store.IsJtiRevokedAsync(jti, _ct);
        Assert.True(isRevoked);
    }

    [Fact]
    public async Task RevokeJtiAsync_WithNullJti_ThrowsArgumentNullException()
    {
        var store = new InMemoryRevocationStore();
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _ = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            store.RevokeJtiAsync(null!, expiresAt, _ct));
    }

    [Fact]
    public async Task RevokeJtiAsync_WithEmptyJti_ThrowsArgumentException()
    {
        var store = new InMemoryRevocationStore();
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        _ = await Assert.ThrowsAsync<ArgumentException>(() =>
            store.RevokeJtiAsync("", expiresAt, _ct));
    }

    [Fact]
    public async Task RevokeJtiAsync_CalledTwiceWithSameJti_IsIdempotent()
    {
        var store = new InMemoryRevocationStore();
        var jti = "test-jti-duplicate";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        await store.RevokeJtiAsync(jti, expiresAt, _ct);
        await store.RevokeJtiAsync(jti, expiresAt, _ct);

        var isRevoked = await store.IsJtiRevokedAsync(jti, _ct);
        Assert.True(isRevoked);
    }

    [Fact]
    public async Task RevokeJtiAsync_TokenStillValidWithinClockSkew_RemainsRevoked()
    {
        using var store = new InMemoryRevocationStore();
        const string jti = "revoked-within-clock-skew";

        // The verifier permits up to five minutes of expiration tolerance.
        // Revocation must not disappear merely because the raw exp has passed.
        await store.RevokeJtiAsync(jti, DateTimeOffset.UtcNow.AddSeconds(-30), _ct);

        Assert.True(await store.IsJtiRevokedAsync(jti, _ct));
        await store.CleanupExpiredEntriesAsync(_ct);
        Assert.True(await store.IsJtiRevokedAsync(jti, _ct));
    }

    [Fact]
    public async Task RevokeJtiAsync_ShorterSecondExpiration_DoesNotUnrevokeActiveToken()
    {
        using var store = new InMemoryRevocationStore();
        const string jti = "monotonic-revocation";
        var now = DateTimeOffset.UtcNow;

        await store.RevokeJtiAsync(jti, now.AddHours(1), _ct);
        await store.RevokeJtiAsync(jti, now.AddMinutes(-1), _ct);
        await store.CleanupExpiredEntriesAsync(_ct);

        Assert.True(await store.IsJtiRevokedAsync(jti, _ct));
    }

    [Fact]
    public async Task ConcurrentEarlierRevocationsAndCleanup_CannotEraseLiveMarker()
    {
        using var store = new InMemoryRevocationStore();
        const string jti = "concurrent-monotonic-revocation";
        var now = DateTimeOffset.UtcNow;
        await store.RevokeJtiAsync(jti, now.AddHours(1), _ct);

        var operations = Enumerable.Range(0, 64)
            .Select(index => Task.Run(async () =>
            {
                if (index % 2 == 0)
                {
                    await store.RevokeJtiAsync(jti, now.AddMinutes(-1), _ct);
                }
                else
                {
                    await store.CleanupExpiredEntriesAsync(_ct);
                }
            }, _ct));

        await Task.WhenAll(operations);

        Assert.True(await store.IsJtiRevokedAsync(jti, _ct));
    }

    [Fact]
    public async Task IsJtiRevokedAsync_ExpiredMarker_ReturnsFalseBeforeBackgroundCleanup()
    {
        using var store = new InMemoryRevocationStore();
        const string jti = "expired-without-cleanup";

        await store.RevokeJtiAsync(jti, DateTimeOffset.UtcNow.AddMinutes(-6), _ct);

        // A stored expired marker must not block verification until the periodic
        // five-minute cleanup runs. The previous ContainsKey implementation did.
        Assert.False(await store.IsJtiRevokedAsync(jti, _ct));
    }

    [Fact]
    public async Task IsJtiRevokedAsync_ExtendedMarker_RemainsRevokedBeforeBackgroundCleanup()
    {
        using var store = new InMemoryRevocationStore();
        const string jti = "extended-without-cleanup";
        var now = DateTimeOffset.UtcNow;

        await store.RevokeJtiAsync(jti, now.AddMinutes(-1), _ct);
        await store.RevokeJtiAsync(jti, now.AddHours(1), _ct);

        Assert.True(await store.IsJtiRevokedAsync(jti, _ct));
    }

    [Fact]
    public async Task IsJtiRevokedAsync_WithNonExistentJti_ReturnsFalse()
    {
        var store = new InMemoryRevocationStore();

        var isRevoked = await store.IsJtiRevokedAsync("non-existent-jti", _ct);

        Assert.False(isRevoked);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Key ID Revocation Tests
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task RevokeKeyAsync_WithValidKeyId_StoresEntry()
    {
        var store = new InMemoryRevocationStore();
        var keyId = "test-key-2024";

        await store.RevokeKeyAsync(keyId, _ct);

        var isRevoked = await store.IsKeyRevokedAsync(keyId, _ct);
        Assert.True(isRevoked);
    }

    [Fact]
    public async Task RevokeKeyAsync_WithNullKeyId_ThrowsArgumentNullException()
    {
        var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            store.RevokeKeyAsync(null!, _ct));
    }

    [Fact]
    public async Task UnrevokeKeyAsync_AfterRevocation_AllowsKeyAgain()
    {
        var store = new InMemoryRevocationStore();
        var keyId = "test-key-unrevoke";

        await store.RevokeKeyAsync(keyId, _ct);
        var revokedBefore = await store.IsKeyRevokedAsync(keyId, _ct);
        await store.UnrevokeKeyAsync(keyId, _ct);
        var revokedAfter = await store.IsKeyRevokedAsync(keyId, _ct);

        Assert.True(revokedBefore);
        Assert.False(revokedAfter);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // User ID Revocation Tests
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task RevokeUserAsync_WithValidUserId_StoresEntry()
    {
        var store = new InMemoryRevocationStore();
        var userId = "alice@example.com";

        await store.RevokeUserAsync(userId, _ct);

        var isRevoked = await store.IsUserRevokedAsync(userId, _ct);
        Assert.True(isRevoked);
    }

    [Fact]
    public async Task RevokeUserAsync_WithNullUserId_ThrowsArgumentNullException()
    {
        var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            store.RevokeUserAsync(null!, _ct));
    }

    [Fact]
    public async Task UnrevokeUserAsync_AfterRevocation_AllowsUserAgain()
    {
        var store = new InMemoryRevocationStore();
        var userId = "charlie@example.com";

        await store.RevokeUserAsync(userId, _ct);
        var revokedBefore = await store.IsUserRevokedAsync(userId, _ct);
        await store.UnrevokeUserAsync(userId, _ct);
        var revokedAfter = await store.IsUserRevokedAsync(userId, _ct);

        Assert.True(revokedBefore);
        Assert.False(revokedAfter);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public async Task IsJtiRevokedAsync_WithBlankIdentifier_ThrowsArgumentException(string invalid)
    {
        using var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAsync<ArgumentException>(() => store.IsJtiRevokedAsync(invalid, _ct));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public async Task IsKeyRevokedAsync_WithBlankIdentifier_ThrowsArgumentException(string invalid)
    {
        using var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAsync<ArgumentException>(() => store.IsKeyRevokedAsync(invalid, _ct));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public async Task UnrevokeKeyAsync_WithBlankIdentifier_ThrowsArgumentException(string invalid)
    {
        using var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAsync<ArgumentException>(() => store.UnrevokeKeyAsync(invalid, _ct));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public async Task IsUserRevokedAsync_WithBlankIdentifier_ThrowsArgumentException(string invalid)
    {
        using var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAsync<ArgumentException>(() => store.IsUserRevokedAsync(invalid, _ct));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public async Task UnrevokeUserAsync_WithBlankIdentifier_ThrowsArgumentException(string invalid)
    {
        using var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAsync<ArgumentException>(() => store.UnrevokeUserAsync(invalid, _ct));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup Tests
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CleanupExpiredEntriesAsync_RemovesExpiredJtis()
    {
        var store = new InMemoryRevocationStore();
        var expiredJti = "expired-jti";
        var activeJti = "active-jti";
        var expiredTime = DateTimeOffset.UtcNow.AddMinutes(-6);
        var futureTime = DateTimeOffset.UtcNow.AddHours(1);

        await store.RevokeJtiAsync(expiredJti, expiredTime, _ct);
        await store.RevokeJtiAsync(activeJti, futureTime, _ct);

        await Task.Delay(100, _ct);
        await store.CleanupExpiredEntriesAsync(_ct);

        var expiredRevoked = await store.IsJtiRevokedAsync(expiredJti, _ct);
        var activeRevoked = await store.IsJtiRevokedAsync(activeJti, _ct);

        Assert.False(expiredRevoked);
        Assert.True(activeRevoked);
    }

    [Fact]
    public async Task Should_ReclaimThousandsOfExpiredRevocations_WithoutProportionalTemporaryAllocations()
    {
        // A cleanup with 10,000 expired entries must not copy them into an
        // intermediate list. KeyValuePair<string, DateTimeOffset> alone would
        // consume about 24 bytes per entry before List capacity overhead.
        using var store = new InMemoryRevocationStore();
        var token = TestContext.Current.CancellationToken;
        var now = DateTimeOffset.UtcNow;

        // Warm up the cleanup path before measuring (without seeded entries).
        await store.CleanupExpiredEntriesAsync(token);

        for (var i = 0; i < 20_000; i++)
        {
            var expiration = i % 2 == 0 ? now.AddMinutes(-6) : now.AddHours(1);
            await store.RevokeJtiAsync($"cleanup-{i}", expiration, token);
        }

        // The method synchronously returns a completed task. Measure only its
        // enumeration/removal work, excluding setup and assertion allocations.
        var before = GC.GetAllocatedBytesForCurrentThread();
        var cleanup = store.CleanupExpiredEntriesAsync(token);
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - before;
        await cleanup;

        Assert.True(allocatedBytes < 32 * 1024,
            $"Revocation cleanup allocated {allocatedBytes} bytes for expired entries.");
        Assert.False(await store.IsJtiRevokedAsync("cleanup-0", token));
        Assert.True(await store.IsJtiRevokedAsync("cleanup-1", token));
        Assert.True(await store.IsJtiRevokedAsync("cleanup-19999", token));
    }

    [Fact]
    public async Task CleanupExpiredEntriesAsync_DoesNotRemoveKeyRevocations()
    {
        var store = new InMemoryRevocationStore();
        var keyId = "test-key-persist";

        await store.RevokeKeyAsync(keyId, _ct);
        await store.CleanupExpiredEntriesAsync(_ct);

        var isRevoked = await store.IsKeyRevokedAsync(keyId, _ct);
        Assert.True(isRevoked);
    }

    [Fact]
    public void Dispose_WhenCalledTwice_DoesNotThrow()
    {
        var store = new InMemoryRevocationStore();

        store.Dispose();
        store.Dispose();
    }

    [Fact]
    public async Task Dispose_WhenCalledConcurrently_DoesNotThrow()
    {
        var store = new InMemoryRevocationStore();
        var disposals = Enumerable.Range(0, 32)
            .Select(_ => Task.Run(store.Dispose))
            .ToArray();

        await Task.WhenAll(disposals);
        store.Dispose();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Concurrency Tests
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ConcurrentRevocations_AreThreadSafe()
    {
        var store = new InMemoryRevocationStore();
        var tasks = new List<Task>();

        for (int i = 0; i < 100; i++)
        {
            var jti = $"jti-{i}";
            var expiresAt = DateTimeOffset.UtcNow.AddHours(1);
            tasks.Add(store.RevokeJtiAsync(jti, expiresAt, _ct));
        }

        await Task.WhenAll(tasks);

        for (int i = 0; i < 100; i++)
        {
            var jti = $"jti-{i}";
            var isRevoked = await store.IsJtiRevokedAsync(jti, _ct);
            Assert.True(isRevoked);
        }
    }
}
