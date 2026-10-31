using HeroSdJwt.Verification.Revocation;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Cancelled administrative requests must not clear existing revocations.
/// </summary>
public class RevocationUnrevokeCancellationTests
{
    [Fact]
    public async Task Should_PreserveKeyRevocation_WhenUnrevokeIsCancelled()
    {
        using var store = new InMemoryRevocationStore();
        const string keyId = "cancelled-key-unrevoke";
        await store.RevokeKeyAsync(keyId, TestContext.Current.CancellationToken);

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => store.UnrevokeKeyAsync(keyId, cancellation.Token));

        Assert.True(await store.IsKeyRevokedAsync(keyId, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Should_PreserveUserRevocation_WhenUnrevokeIsCancelled()
    {
        using var store = new InMemoryRevocationStore();
        const string userId = "cancelled-user-unrevoke";
        await store.RevokeUserAsync(userId, TestContext.Current.CancellationToken);

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => store.UnrevokeUserAsync(userId, cancellation.Token));

        Assert.True(await store.IsUserRevokedAsync(userId, TestContext.Current.CancellationToken));
    }
}
