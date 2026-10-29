using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// An external revocation store may include credentials in its diagnostic exceptions.
/// None of that data should escape through public verification exceptions or results.
/// </summary>
public sealed class RevocationStoreErrorDisclosureTests
{
    private const string BACKEND_SECRET = "sensitive-revocation-backend-diagnostic-marker";
    private const string KEY_ID = "revocation-error-key";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("jti", false)]
    [InlineData("jti", true)]
    [InlineData("key", false)]
    [InlineData("key", true)]
    [InlineData("user", false)]
    [InlineData("user", true)]
    public async Task Should_NotExposeBackendDiagnostics_WhenFailClosed(string failAt, bool resolveKey)
    {
        var store = new FaultingRevocationStore(failAt);
        var verifier = TestHelpers.CreateVerifierWithRevocation(
            new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Symmetric,
                Revocation = new RevocationOptions { FailureMode = RevocationFailureMode.FailClosed }
            }, store);
        var presentation = SdJwtIssuerBuilder.Create()
            .WithKeyId(KEY_ID)
            .WithClaim("jti", "revocation-error-token")
            .WithClaim("sub", "revocation-error-user")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();

        // The throwing APIs must not retain a backend exception in InnerException:
        // Exception.ToString() includes every inner exception and may be logged.
        var syncError = Assert.Throws<SdJwtException>(() =>
        {
            if (resolveKey)
            {
                verifier.VerifyPresentation(presentation, ResolveKey);
            }
            else
            {
                verifier.VerifyPresentation(presentation, _signingKey);
            }
        });
        Assert.Equal(ErrorCode.InvalidInput, syncError.ErrorCode);
        Assert.Null(syncError.InnerException);
        Assert.DoesNotContain(BACKEND_SECRET, syncError.ToString(), StringComparison.Ordinal);

        var asyncError = await Assert.ThrowsAsync<SdJwtException>(() => resolveKey
            ? verifier.VerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : verifier.VerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.InvalidInput, asyncError.ErrorCode);
        Assert.Null(asyncError.InnerException);
        Assert.DoesNotContain(BACKEND_SECRET, asyncError.ToString(), StringComparison.Ordinal);

        var syncResult = resolveKey
            ? verifier.TryVerifyPresentation(presentation, ResolveKey)
            : verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(syncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, syncResult.Errors);
        Assert.DoesNotContain(BACKEND_SECRET, syncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var asyncResult = resolveKey
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : await verifier.TryVerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResult.Errors);
        Assert.DoesNotContain(BACKEND_SECRET, asyncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
    }

    private static byte[]? ResolveKey(string keyId) => keyId == KEY_ID ? _signingKey : null;

    private sealed class FaultingRevocationStore(string failAt) : IRevocationStore
    {
        private static Task<bool> FailedLookup() =>
            Task.FromException<bool>(new IOException(BACKEND_SECRET));

        public Task<bool> IsJtiRevokedAsync(
            string jti, CancellationToken cancellationToken = default) =>
            failAt == "jti" ? FailedLookup() : Task.FromResult(false);

        public Task<bool> IsKeyRevokedAsync(
            string keyId, CancellationToken cancellationToken = default) =>
            failAt == "key" ? FailedLookup() : Task.FromResult(false);

        public Task<bool> IsUserRevokedAsync(
            string userId, CancellationToken cancellationToken = default) =>
            failAt == "user" ? FailedLookup() : Task.FromResult(false);

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
