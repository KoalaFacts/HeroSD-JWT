using HeroSdJwt.Verification.Revocation;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Canceling an administrative unrevocation must never reactivate credentials.
/// </summary>
public sealed class RevocationUnrevokeCancellationTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Should_PreserveRevocation_WhenUnrevokeIsCanceled(bool isKeyRevocation)
    {
        const string identifier = "emergency-revocation";
        using var store = new InMemoryRevocationStore();
        var cancellationToken = TestContext.Current.CancellationToken;

        if (isKeyRevocation)
        {
            await store.RevokeKeyAsync(identifier, cancellationToken);
        }
        else
        {
            await store.RevokeUserAsync(identifier, cancellationToken);
        }

        using var canceled = new CancellationTokenSource();
        canceled.Cancel();

        var exception = await Record.ExceptionAsync(async () =>
        {
            if (isKeyRevocation)
            {
                await store.UnrevokeKeyAsync(identifier, canceled.Token);
            }
            else
            {
                await store.UnrevokeUserAsync(identifier, canceled.Token);
            }
        });

        var remainsRevoked = isKeyRevocation
            ? await store.IsKeyRevokedAsync(identifier, cancellationToken)
            : await store.IsUserRevokedAsync(identifier, cancellationToken);

        Assert.True(remainsRevoked, "Canceled administrative unrevocation must not erase a live revocation.");
        Assert.IsAssignableFrom<OperationCanceledException>(exception);
    }
}
