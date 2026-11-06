using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A failing revocation lookup under an explicit fail-open policy must not
/// suppress independent key and subject revocation decisions.
/// </summary>
public sealed class PartialRevocationStoreFailureTests
{
    private const string KEY_ID = "partial-revocation-key";
    private const string JTI = "partial-revocation-jti";
    private const string SUBJECT = "partial-revocation-subject";
    private const string BACKEND_SECRET = "private-revocation-store-diagnostic";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("jti", "key", ErrorCode.TokenRevokedByKey)]
    [InlineData("jti", "user", ErrorCode.TokenRevokedByUser)]
    [InlineData("key", "user", ErrorCode.TokenRevokedByUser)]
    public async Task Should_RejectRevokedCredential_WhenEarlierLookupFailsOpen(
        string failingLookup, string revokedLookup, ErrorCode expectedError)
    {
        var store = new PartialFailureStore(failingLookup, revokedLookup);
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(expectedError, direct.Errors);
        Assert.DoesNotContain(BACKEND_SECRET, direct.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var resolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(resolved.IsValid);
        Assert.Contains(expectedError, resolved.Errors);
        Assert.DoesNotContain(BACKEND_SECRET, resolved.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        Assert.Equal(2, store.GetLookupCount(revokedLookup));
    }

    [Fact]
    public void Should_AllowUnrevokedCredential_WhenOnlyJtiLookupFailsOpen()
    {
        var store = new PartialFailureStore("jti", revokedLookup: null);
        var verifier = CreateVerifier(store);

        var result = verifier.TryVerifyPresentation(CreatePresentation(), _signingKey);

        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.Equal(1, store.GetLookupCount("key"));
        Assert.Equal(1, store.GetLookupCount("user"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_RejectCredential_WhenRevocationStoreIsDisposedDespiteFailOpen(bool useKeyResolver)
    {
        // A disposed built-in store throws ObjectDisposedException on every lookup.
        // That is a broken service lifetime, not an availability-first backend outage.
        using var store = new InMemoryRevocationStore();
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation();
        store.Dispose();

        var result = useKeyResolver
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.DoesNotContain(nameof(InMemoryRevocationStore), result.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
    }


    [Theory]
    [InlineData("jti", false, false)]
    [InlineData("jti", true, true)]
    [InlineData("key", false, true)]
    [InlineData("key", true, false)]
    [InlineData("user", false, false)]
    [InlineData("user", true, true)]
    public async Task Should_RejectUnsupportedRevocationLookup_DespiteFailOpen(
        string lookup, bool resolveKey, bool notImplemented)
    {
        // Unsupported operations are broken provider contracts rather than
        // transient outages. Neither exception detail may reach callers.
        var failure = notImplemented
            ? (Exception)new NotImplementedException(BACKEND_SECRET)
            : new NotSupportedException(BACKEND_SECRET);
        var store = new PartialFailureStore(lookup, revokedLookup: null, failure);
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation();

        var result = resolveKey
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.DoesNotContain(BACKEND_SECRET, result.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(1, store.GetLookupCount(lookup));
    }


    [Theory]
    [InlineData("jti", false)]
    [InlineData("jti", true)]
    [InlineData("key", false)]
    [InlineData("key", true)]
    [InlineData("user", false)]
    [InlineData("user", true)]
    public async Task Should_RejectInvalidProviderState_WhenRevocationIsFailOpen(
        string lookup, bool resolveKey)
    {
        // A store rejecting a lookup because it is in an invalid state is not
        // reporting a transient outage. All three revocation checks fail closed.
        var store = new PartialFailureStore(
            lookup, revokedLookup: null, new InvalidOperationException(BACKEND_SECRET));
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation();

        var result = resolveKey
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.DoesNotContain(BACKEND_SECRET, result.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(1, store.GetLookupCount(lookup));
    }

    [Theory]
    [InlineData("jti", false)]
    [InlineData("jti", true)]
    [InlineData("key", false)]
    [InlineData("key", true)]
    [InlineData("user", false)]
    [InlineData("user", true)]
    public async Task Should_RejectMalformedRevocationRecord_DespiteFailOpen(
        string lookup, bool resolveKey)
    {
        // A backend parsing error is not evidence that the token is not revoked.
        const string diagnostic = BACKEND_SECRET;
        var store = new PartialFailureStore(
            lookup, revokedLookup: null, new FormatException(diagnostic));
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation();

        var result = resolveKey
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.DoesNotContain(diagnostic, result.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(1, store.GetLookupCount(lookup));
    }

    [Fact]
    public void Should_AllowTransientRevocationTimeout_WhenFailOpen()
    {
        var store = new PartialFailureStore(
            "jti", revokedLookup: null, new TimeoutException(BACKEND_SECRET));
        var verifier = CreateVerifier(store);

        var result = verifier.TryVerifyPresentation(CreatePresentation(), _signingKey);

        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.Equal(1, store.GetLookupCount("key"));
        Assert.Equal(1, store.GetLookupCount("user"));
    }

    private static SdJwtVerifier CreateVerifier(IRevocationStore store) =>
        TestHelpers.CreateVerifierWithRevocation(
            new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Symmetric,
                Revocation = new RevocationOptions
                {
                    FailureMode = RevocationFailureMode.FailOpen
                }
            }, store);

    private static string CreatePresentation() =>
        SdJwtIssuerBuilder.Create()
            .WithKeyId(KEY_ID)
            .WithClaim("jti", JTI)
            .WithClaim("sub", SUBJECT)
            .SignWithHmac(_signingKey)
            .Build()
            .ToCombinedFormat();

    private static byte[]? ResolveKey(string keyId) =>
        keyId == KEY_ID ? _signingKey : null;

    private sealed class PartialFailureStore(string failingLookup, string? revokedLookup, Exception? failure = null) : IRevocationStore
    {
        private int _jtiReads;
        private int _keyReads;
        private int _userReads;

        public int GetLookupCount(string lookup) => lookup switch
        {
            "jti" => _jtiReads,
            "key" => _keyReads,
            "user" => _userReads,
            _ => throw new ArgumentOutOfRangeException(nameof(lookup))
        };

        private Task<bool> LookupAsync(string lookup)
        {
            if (lookup == failingLookup)
            {
                return Task.FromException<bool>(failure ?? new IOException(BACKEND_SECRET));
            }

            return Task.FromResult(lookup == revokedLookup);
        }

        public Task<bool> IsJtiRevokedAsync(string jti, CancellationToken cancellationToken = default)
        {
            _jtiReads++;
            return LookupAsync("jti");
        }

        public Task<bool> IsKeyRevokedAsync(string keyId, CancellationToken cancellationToken = default)
        {
            _keyReads++;
            return LookupAsync("key");
        }

        public Task<bool> IsUserRevokedAsync(string userId, CancellationToken cancellationToken = default)
        {
            _userReads++;
            return LookupAsync("user");
        }

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
