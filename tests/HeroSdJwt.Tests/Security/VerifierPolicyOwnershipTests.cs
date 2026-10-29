using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A verifier's authorization policy must not change when a caller mutates
/// the list or revocation settings supplied to its constructor.
/// </summary>
public class VerifierPolicyOwnershipTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public void Should_KeepOriginalAudienceRestriction_WhenSourceListChanges()
    {
        var audiences = new List<string> { "trusted-service" };
        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric,
            ExpectedAudiences = audiences
        });

        var presentation = CreatePresentation();

        Assert.False(verifier.TryVerifyPresentation(presentation, _signingKey).IsValid);

        // A shared mutable IReadOnlyList must not turn an already-configured
        // verifier into one that accepts a different audience.
        audiences.Clear();
        audiences.Add("other-service");

        var afterMutation = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(afterMutation.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, afterMutation.Errors);
    }

    [Fact]
    public void Should_KeepFailClosedRevocationPolicy_WhenSourceOptionsChange()
    {
        var revocation = new RevocationOptions
        {
            FailureMode = RevocationFailureMode.FailClosed
        };
        var verifier = TestHelpers.CreateVerifierWithRevocation(
            new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Symmetric,
                Revocation = revocation
            },
            new UnavailableRevocationStore());

        var presentation = CreatePresentation();

        Assert.False(verifier.TryVerifyPresentation(presentation, _signingKey).IsValid);

        // Mutating the caller's original options must not silently weaken
        // the verifier's fail-closed behavior during a revocation outage.
        revocation.FailureMode = RevocationFailureMode.FailOpen;

        var afterMutation = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(afterMutation.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, afterMutation.Errors);
    }

    private static string CreatePresentation() =>
        SdJwtIssuerBuilder.Create()
            .WithClaim("aud", "other-service")
            .WithClaim("jti", "stable-verifier-policy")
            .WithClaim("sub", "alice")
            .SignWithHmac(_signingKey)
            .Build()
            .ToCombinedFormat();

    private sealed class UnavailableRevocationStore : IRevocationStore
    {
        public Task RevokeJtiAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<bool> IsJtiRevokedAsync(string jti, CancellationToken cancellationToken = default) =>
            Task.FromException<bool>(new InvalidOperationException("Revocation backend unavailable"));

        public Task RevokeKeyAsync(string keyId, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<bool> IsKeyRevokedAsync(string keyId, CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task UnrevokeKeyAsync(string keyId, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task RevokeUserAsync(string userId, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<bool> IsUserRevokedAsync(string userId, CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task UnrevokeUserAsync(string userId, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task CleanupExpiredEntriesAsync(CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
