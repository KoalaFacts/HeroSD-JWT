using HeroSdJwt.Exceptions;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Replay-cache failures must follow the caller's explicit availability policy,
/// without converting canceled admissions or actual replays into successes.
/// </summary>
public sealed class ReplayCacheFailureModeTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(value => (byte)value)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_AdmitVerifiedCredential_WhenCacheOutageIsExplicitlyFailOpen(bool asyncVerification)
    {
        var cache = new FaultingCache(new IOException("backend unavailable"));
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithReplayProtection(new JtiValidator(cache, new ReplayProtectionOptions
            {
                Enabled = true,
                FailureMode = CacheFailureMode.FailOpen
            }))
            .Build();

        var presentation = SdJwtIssuerBuilder.Create()
            .WithClaim("iss", "https://issuer.example.test")
            .WithClaim("jti", "outage-test-token")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();

        var result = asyncVerification
            ? await verifier.TryVerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.Equal(1, cache.Attempts);
    }

    [Fact]
    public async Task Should_PropagateCacheFailure_WhenPolicyIsFailClosed()
    {
        var cache = new FaultingCache(new IOException("backend unavailable"));
        var validator = new JtiValidator(cache, NewOptions(CacheFailureMode.FailClosed));

        await Assert.ThrowsAsync<IOException>(() =>
            validator.ValidateAsync(ValidClaims(), TestContext.Current.CancellationToken));
        Assert.Equal(1, cache.Attempts);
    }

    [Fact]
    public async Task Should_PropagateBackendCancellation_EvenWhenPolicyIsFailOpen()
    {
        var cache = new FaultingCache(new OperationCanceledException("backend canceled"));
        var validator = new JtiValidator(cache, NewOptions(CacheFailureMode.FailOpen));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            validator.ValidateAsync(ValidClaims(), TestContext.Current.CancellationToken));
        Assert.Equal(1, cache.Attempts);
    }

    [Fact]
    public async Task Should_RejectInvalidCacheKey_WhenPolicyIsFailOpen()
    {
        // A provider refusing an invalid key is not a temporary storage outage.
        // Accepting the credential would bypass replay-marker admission.
        var failure = new ArgumentException("Replay cache key cannot be stored", "jti");
        var cache = new FaultingCache(failure);
        var validator = new JtiValidator(cache, NewOptions(CacheFailureMode.FailOpen));

        var observed = await Assert.ThrowsAsync<ArgumentException>(() =>
            validator.ValidateAsync(ValidClaims(), TestContext.Current.CancellationToken));

        Assert.Same(failure, observed);
        Assert.Equal(1, cache.Attempts);
    }

    [Fact]
    public async Task Should_RejectProviderDomainValidation_WhenPolicyIsFailOpen()
    {
        var failure = new SdJwtException("Invalid replay marker", ErrorCode.InvalidInput);
        var cache = new FaultingCache(failure);
        var validator = new JtiValidator(cache, NewOptions(CacheFailureMode.FailOpen));

        var observed = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(ValidClaims(), TestContext.Current.CancellationToken));

        Assert.Same(failure, observed);
        Assert.Equal(1, cache.Attempts);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_RejectDisposedCustomReplayCache_DespiteFailOpen(bool resolveKey)
    {
        // A disposed custom cache cannot track replay admissions. This is a
        // broken service lifetime, not an availability-first backend outage.
        const string backendDiagnostic = "private-disposed-replay-cache-diagnostic";
        const string keyId = "disposed-custom-cache-key";
        var cache = new FaultingCache(new ObjectDisposedException("custom-replay-cache", backendDiagnostic));
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithReplayProtection(new JtiValidator(cache, NewOptions(CacheFailureMode.FailOpen)))
            .Build();
        var presentation = SdJwtIssuerBuilder.Create()
            .WithKeyId(keyId)
            .WithClaim("iss", "https://issuer.example.test")
            .WithClaim("jti", "disposed-custom-cache-token")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();

        var result = resolveKey
            ? await verifier.TryVerifyPresentationAsync(
                presentation, id => id == keyId ? _signingKey : null,
                cancellationToken: TestContext.Current.CancellationToken)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.DoesNotContain(backendDiagnostic, result.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(1, cache.Attempts);
    }


    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Should_RejectUnsupportedReplayAdmission_DespiteFailOpen(
        bool resolveKey, bool notImplemented)
    {
        // A provider without atomic admission support cannot record a replay,
        // regardless of an availability-first policy for transient outages.
        const string diagnostic = "private-unsupported-replay-provider-diagnostic";
        const string keyId = "unsupported-replay-provider";
        var failure = notImplemented
            ? (Exception)new NotImplementedException(diagnostic)
            : new NotSupportedException(diagnostic);
        var cache = new FaultingCache(failure);
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithReplayProtection(new JtiValidator(cache, NewOptions(CacheFailureMode.FailOpen)))
            .Build();
        var presentation = SdJwtIssuerBuilder.Create()
            .WithKeyId(keyId)
            .WithClaim("iss", "https://issuer.example.test")
            .WithClaim("jti", "unsupported-replay-token")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();

        var result = resolveKey
            ? await verifier.TryVerifyPresentationAsync(
                presentation, id => id == keyId ? _signingKey : null,
                cancellationToken: TestContext.Current.CancellationToken)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.DoesNotContain(diagnostic, result.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(1, cache.Attempts);
    }

    [Fact]
    public async Task Should_PropagateCacheReportedReplay_WhenPolicyIsFailOpen()
    {
        // A custom atomic provider may report a known replay with the domain
        // exception rather than a false result. This is not a backend outage.
        var cache = new FaultingCache(
            new ReplayAttackException("test-jti", "https://issuer.example.test"));
        var validator = new JtiValidator(cache, NewOptions(CacheFailureMode.FailOpen));

        var replay = await Assert.ThrowsAsync<ReplayAttackException>(() =>
            validator.ValidateAsync(ValidClaims(), TestContext.Current.CancellationToken));

        Assert.Equal("test-jti", replay.Jti);
        Assert.Equal("https://issuer.example.test", replay.Issuer);
        Assert.Equal(1, cache.Attempts);
    }

    [Fact]
    public async Task Should_RejectRealReplay_EvenWhenPolicyIsFailOpen()
    {
        var validator = new JtiValidator(new RejectingCache(), NewOptions(CacheFailureMode.FailOpen));

        await Assert.ThrowsAsync<ReplayAttackException>(() =>
            validator.ValidateAsync(ValidClaims(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Should_RejectUndefinedReplayFailureMode_BeforeVerification()
    {
        var options = NewOptions((CacheFailureMode)42);

        Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Throws<InvalidOperationException>(() => new JtiValidator(new RejectingCache(), options));
    }

    private static ReplayProtectionOptions NewOptions(CacheFailureMode mode) => new()
    {
        Enabled = true,
        FailureMode = mode
    };

    private static Dictionary<string, JsonElement> ValidClaims() => new()
    {
        ["iss"] = JsonSerializer.SerializeToElement("https://issuer.example.test"),
        ["jti"] = JsonSerializer.SerializeToElement("test-jti"),
        ["exp"] = JsonSerializer.SerializeToElement(DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
    };

    private sealed class FaultingCache(Exception exception) : IJtiCache
    {
        public int Attempts { get; private set; }

        public Task<bool> TryAddAsync(
            string issuer, string jti, TimeSpan ttl, CancellationToken cancellationToken = default)
        {
            Attempts++;
            return Task.FromException<bool>(exception);
        }

        public Task<bool> ExistsAsync(
            string issuer, string jti, CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task RemoveAsync(
            string issuer, string jti, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class RejectingCache : IJtiCache
    {
        public Task<bool> TryAddAsync(
            string issuer, string jti, TimeSpan ttl, CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task<bool> ExistsAsync(
            string issuer, string jti, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);

        public Task RemoveAsync(
            string issuer, string jti, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
