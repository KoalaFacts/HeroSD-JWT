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
    private const string KeyId = "partial-revocation-key";
    private const string Jti = "partial-revocation-jti";
    private const string Subject = "partial-revocation-subject";
    private const string BackendSecret = "private-revocation-store-diagnostic";
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
        Assert.DoesNotContain(BackendSecret, direct.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var resolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(resolved.IsValid);
        Assert.Contains(expectedError, resolved.Errors);
        Assert.DoesNotContain(BackendSecret, resolved.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

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
            .WithKeyId(KeyId)
            .WithClaim("jti", Jti)
            .WithClaim("sub", Subject)
            .SignWithHmac(_signingKey)
            .Build()
            .ToCombinedFormat();

    private static byte[]? ResolveKey(string keyId) =>
        keyId == KeyId ? _signingKey : null;

    private sealed class PartialFailureStore(string failingLookup, string? revokedLookup) : IRevocationStore
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
                return Task.FromException<bool>(new IOException(BackendSecret));
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
