using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Replay caches may wrap external stores whose failure messages include
/// connection credentials. A rejected presentation must not reveal them.
/// </summary>
public class ReplayCacheErrorDisclosureTests
{
    private const string BACKEND_SECRET = "sensitive-replay-backend-diagnostic-marker";
    private const string KEY_ID = "replay-error-key";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_NotExposeBackendFailureDetails_WhenReplayCacheAdmissionFails(bool resolveKey)
    {
        var cache = new FaultingCache();
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithReplayProtection(new JtiValidator(cache, new ReplayProtectionOptions { Enabled = true }))
            .Build();
        var presentation = SdJwtIssuerBuilder.Create()
            .WithKeyId(KEY_ID)
            .WithClaim("iss", "https://issuer.example.test")
            .WithClaim("jti", "replay-error-token")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();

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
        Assert.Equal(2, cache.AdmissionAttempts);
    }

    private static byte[]? ResolveKey(string keyId) => keyId == KEY_ID ? _signingKey : null;

    private sealed class FaultingCache : IJtiCache
    {
        public int AdmissionAttempts { get; private set; }

        public Task<bool> TryAddAsync(
            string issuer, string jti, TimeSpan ttl, CancellationToken cancellationToken = default)
        {
            AdmissionAttempts++;
            return Task.FromException<bool>(new IOException(BACKEND_SECRET));
        }

        public Task<bool> ExistsAsync(
            string issuer, string jti, CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task RemoveAsync(
            string issuer, string jti, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
