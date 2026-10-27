using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Fail-open is a policy for revocation storage outages, not for canceled work.
/// A canceled lookup must never turn an unverified token into an accepted one.
/// </summary>
public class RevocationCancellationTests
{
    private const string KEY_ID = "revocation-cancellation-key";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    [InlineData(false, true, true)]
    [InlineData(true, false, false)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    [InlineData(true, true, true)]
    public async Task Should_NotAdmitCanceledRevocationLookup_WhenFailOpen(
        bool resolveKey, bool tryApi, bool cancelCaller)
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var store = new FaultingRevocationStore(
            ioFailure: false,
            cancelOnLookup: cancelCaller ? cancellation : null);
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation();

        if (tryApi)
        {
            var result = resolveKey
                ? await verifier.TryVerifyPresentationAsync(
                    presentation, ResolveKey, cancellationToken: cancellation.Token)
                : await verifier.TryVerifyPresentationAsync(
                    presentation, _signingKey, cancellationToken: cancellation.Token);

            Assert.False(result.IsValid, "A canceled revocation check must not admit a credential.");
            Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        }
        else
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => resolveKey
                ? verifier.VerifyPresentationAsync(
                    presentation, ResolveKey, cancellationToken: cancellation.Token)
                : verifier.VerifyPresentationAsync(
                    presentation, _signingKey, cancellationToken: cancellation.Token));
        }

        Assert.Equal(1, store.LookupCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_NotAdmitCanceledRevocationLookup_ThroughSyncApi(bool resolveKey)
    {
        var store = new FaultingRevocationStore(ioFailure: false);
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation();

        var result = resolveKey
            ? verifier.TryVerifyPresentation(presentation, ResolveKey)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.Equal(1, store.LookupCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_KeepFailOpenForActualStorageFailures(bool resolveKey)
    {
        var store = new FaultingRevocationStore(ioFailure: true);
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation();

        var result = resolveKey
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : await verifier.TryVerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.Equal(1, store.LookupCount);
    }


    [Theory]
    [InlineData("jti", false, false)]
    [InlineData("jti", false, true)]
    [InlineData("jti", true, false)]
    [InlineData("jti", true, true)]
    [InlineData("key", false, false)]
    [InlineData("key", false, true)]
    [InlineData("key", true, false)]
    [InlineData("key", true, true)]
    [InlineData("user", false, false)]
    [InlineData("user", false, true)]
    [InlineData("user", true, false)]
    [InlineData("user", true, true)]
    public async Task Should_NotAdmitCanceledRevocationLookup_WhenStoreIgnoresCancellation(
        string cancelAt, bool resolveKey, bool tryApi)
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var store = new CancellationIgnoringRevocationStore(cancellation, cancelAt);
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation();

        if (tryApi)
        {
            var result = resolveKey
                ? await verifier.TryVerifyPresentationAsync(
                    presentation, ResolveKey, cancellationToken: cancellation.Token)
                : await verifier.TryVerifyPresentationAsync(
                    presentation, _signingKey, cancellationToken: cancellation.Token);

            Assert.False(result.IsValid, "A canceled revocation read must never accept the credential.");
            Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        }
        else
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => resolveKey
                ? verifier.VerifyPresentationAsync(
                    presentation, ResolveKey, cancellationToken: cancellation.Token)
                : verifier.VerifyPresentationAsync(
                    presentation, _signingKey, cancellationToken: cancellation.Token));
        }

        // Stop as soon as the canceled read completes; don't access another backend.
        Assert.Equal(cancelAt == "jti" ? 1 : cancelAt == "key" ? 2 : 3, store.LookupCount);
    }

    private static SdJwtVerifier CreateVerifier(IRevocationStore store) =>
        TestHelpers.CreateVerifierWithRevocation(
            new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Symmetric,
                Revocation = new RevocationOptions { FailureMode = RevocationFailureMode.FailOpen }
            }, store);

    private static byte[]? ResolveKey(string keyId) =>
        keyId == KEY_ID ? _signingKey : null;

    private static string CreatePresentation() =>
        SdJwtIssuerBuilder.Create()
            .WithKeyId(KEY_ID)
            .WithClaim("jti", "cancellation-token-id")
            .WithClaim("sub", "cancellation-user")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();

    private sealed class FaultingRevocationStore(
        bool ioFailure, CancellationTokenSource? cancelOnLookup = null) : IRevocationStore
    {
        public int LookupCount { get; private set; }

        public Task<bool> IsJtiRevokedAsync(string jti, CancellationToken cancellationToken = default)
        {
            LookupCount++;
            cancelOnLookup?.Cancel();

            // Fault an asynchronous store read, rather than throwing before
            // the verifier can await it.
            return Task.FromException<bool>(ioFailure
                ? new IOException("Revocation backend unavailable")
                : new OperationCanceledException(cancellationToken));
        }

        public Task RevokeJtiAsync(string jti, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RevokeKeyAsync(string keyId,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<bool> IsKeyRevokedAsync(string keyId,
            CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task UnrevokeKeyAsync(string keyId,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RevokeUserAsync(string userId,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<bool> IsUserRevokedAsync(string userId,
            CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task UnrevokeUserAsync(string userId,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task CleanupExpiredEntriesAsync(
            CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    // Some adapters honor cancellation only at call entry and may finish a
    // pending read with false after the request has been canceled.
    private sealed class CancellationIgnoringRevocationStore(
        CancellationTokenSource caller, string cancelAt) : IRevocationStore
    {
        public int LookupCount { get; private set; }

        private Task<bool> Lookup(string kind)
        {
            LookupCount++;
            if (kind == cancelAt)
            {
                caller.Cancel();
            }

            return Task.FromResult(false);
        }

        public Task<bool> IsJtiRevokedAsync(string jti,
            CancellationToken cancellationToken = default) => Lookup("jti");

        public Task<bool> IsKeyRevokedAsync(string keyId,
            CancellationToken cancellationToken = default) => Lookup("key");

        public Task<bool> IsUserRevokedAsync(string userId,
            CancellationToken cancellationToken = default) => Lookup("user");

        public Task RevokeJtiAsync(string jti, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RevokeKeyAsync(string keyId,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task UnrevokeKeyAsync(string keyId,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RevokeUserAsync(string userId,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task UnrevokeUserAsync(string userId,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task CleanupExpiredEntriesAsync(
            CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
