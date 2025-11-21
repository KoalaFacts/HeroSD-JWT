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

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup Tests
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CleanupExpiredEntriesAsync_RemovesExpiredJtis()
    {
        var store = new InMemoryRevocationStore();
        var expiredJti = "expired-jti";
        var activeJti = "active-jti";
        var expiredTime = DateTimeOffset.UtcNow.AddSeconds(-1);
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
    public async Task CleanupExpiredEntriesAsync_DoesNotRemoveKeyRevocations()
    {
        var store = new InMemoryRevocationStore();
        var keyId = "test-key-persist";

        await store.RevokeKeyAsync(keyId, _ct);
        await store.CleanupExpiredEntriesAsync(_ct);

        var isRevoked = await store.IsKeyRevokedAsync(keyId, _ct);
        Assert.True(isRevoked);
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
