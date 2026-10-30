using HeroSdJwt.Verification.Revocation;

namespace HeroSdJwt.Tests.Unit.Verification.Revocation;

public class InMemoryRevocationCancellationContractTests
{
    private static readonly CancellationToken _canceled = new(true);

    [Fact]
    public async Task Should_LeaveRevokedKeyBlocked_WhenUnrevokeIsCanceled()
    {
        using var store = new InMemoryRevocationStore();
        await store.RevokeKeyAsync("compromised-key");

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.UnrevokeKeyAsync("compromised-key", _canceled));

        Assert.True(await store.IsKeyRevokedAsync("compromised-key"));
    }

    [Fact]
    public async Task Should_LeaveRevokedUserBlocked_WhenUnrevokeIsCanceled()
    {
        using var store = new InMemoryRevocationStore();
        await store.RevokeUserAsync("suspended-user");

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.UnrevokeUserAsync("suspended-user", _canceled));

        Assert.True(await store.IsUserRevokedAsync("suspended-user"));
    }

    [Fact]
    public async Task Should_RejectCanceledKeyRevocation_WithoutChangingState()
    {
        using var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.RevokeKeyAsync("cancelled-key", _canceled));

        Assert.False(await store.IsKeyRevokedAsync("cancelled-key"));
    }

    [Fact]
    public async Task Should_RejectCanceledUserRevocation_WithoutChangingState()
    {
        using var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.RevokeUserAsync("cancelled-user", _canceled));

        Assert.False(await store.IsUserRevokedAsync("cancelled-user"));
    }

    [Fact]
    public async Task Should_RejectCanceledKeyRevocationLookup()
    {
        using var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.IsKeyRevokedAsync("key", _canceled));
    }

    [Fact]
    public async Task Should_RejectCanceledUserRevocationLookup()
    {
        using var store = new InMemoryRevocationStore();

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.IsUserRevokedAsync("user", _canceled));
    }
}
