using HeroSdJwt.Verification.Revocation;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A revocation administrator must not silently accept a key ID that the
/// verifier will always reject before it can consult the revocation store.
/// </summary>
public class InMemoryRevocationKeyIdAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task Should_RejectKeyIdsOutsideVerifierPolicy_ForAllKeyRevocationOperations(int invalidCase)
    {
        var keyId = invalidCase switch
        {
            0 => "kid\nforged-log-line",
            1 => "kid-\u00e9",
            _ => new string('k', 257)
        };

        using var store = new InMemoryRevocationStore();
        var cancellationToken = TestContext.Current.CancellationToken;

        await Assert.ThrowsAsync<ArgumentException>(() =>
            store.RevokeKeyAsync(keyId, cancellationToken));

        await Assert.ThrowsAsync<ArgumentException>(() =>
            store.IsKeyRevokedAsync(keyId, cancellationToken));

        await Assert.ThrowsAsync<ArgumentException>(() =>
            store.UnrevokeKeyAsync(keyId, cancellationToken));
    }
}
