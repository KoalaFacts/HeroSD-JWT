using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A canceled replay-cache admission must propagate cancellation through the
/// throwing async verification APIs, not masquerade as a malformed credential.
/// The Try APIs must still fail closed rather than accept the presentation.
/// </summary>
public class ReplayCacheCancellationTests
{
    private const string KEY_ID = "replay-cancellation-key";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Should_PropagateCanceledReplayAdmission_ThroughVerifyAsync(
        bool resolveKey, bool cancelCaller)
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var cache = new CancelingCache(cancelCaller ? cancellation : null);
        var verifier = CreateVerifier(cache);
        var presentation = CreatePresentation();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => resolveKey
            ? verifier.VerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: cancellation.Token)
            : verifier.VerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: cancellation.Token));

        Assert.Equal(1, cache.AdmissionAttempts);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Should_FailClosedOnCanceledReplayAdmission_ThroughTryAsync(
        bool resolveKey, bool cancelCaller)
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var cache = new CancelingCache(cancelCaller ? cancellation : null);
        var verifier = CreateVerifier(cache);
        var presentation = CreatePresentation();

        var result = resolveKey
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: cancellation.Token)
            : await verifier.TryVerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: cancellation.Token);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.Equal(1, cache.AdmissionAttempts);
    }

    private static SdJwtVerifier CreateVerifier(IJtiCache cache)
    {
        var replayOptions = new ReplayProtectionOptions { Enabled = true };
        return SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithReplayProtection(new JtiValidator(cache, replayOptions))
            .Build();
    }

    private static byte[]? ResolveKey(string keyId) =>
        keyId == KEY_ID ? _signingKey : null;

    private static string CreatePresentation() =>
        SdJwtIssuerBuilder.Create()
            .WithKeyId(KEY_ID)
            .WithClaim("iss", "https://issuer.example.test")
            .WithClaim("jti", "replay-cancellation-id")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();

    private sealed class CancelingCache(CancellationTokenSource? cancelCaller) : IJtiCache
    {
        public int AdmissionAttempts { get; private set; }

        public Task<bool> TryAddAsync(
            string issuer, string jti, TimeSpan ttl,
            CancellationToken cancellationToken = default)
        {
            AdmissionAttempts++;
            if (cancelCaller != null)
            {
                cancelCaller.Cancel();
                return Task.FromCanceled<bool>(cancellationToken);
            }

            // A cache backend may cancel a read independently of the caller's
            // cancellation token (for example, on an internal timeout).
            return Task.FromException<bool>(new OperationCanceledException("Replay backend canceled admission"));
        }

        public Task<bool> ExistsAsync(
            string issuer, string jti, CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task RemoveAsync(
            string issuer, string jti, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
