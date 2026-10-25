using HeroSdJwt.Exceptions;
using HeroSdJwt.Verification.ReplayProtection;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Deterministic replay-retention boundaries with a controllable clock and
/// admission cache. This is a single-process fixture, not a distributed provider.
/// </summary>
public class ReplayRetentionSecurityTests
{
    private static readonly DateTimeOffset _fixedNow = new(2026, 10, 24, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Should_RejectLongLivedCredential_WhenItsMarkerWouldExpireBeforeTheCredential()
    {
        var clock = new MutableClock(_fixedNow);
        var cache = new RetentionCache(clock);
        var options = new ReplayProtectionOptions { Enabled = true };
        var validator = new JtiValidator(cache, options, clock);
        var claims = Claims(_fixedNow.AddHours(48).ToUnixTimeSeconds());

        var failure = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
        Assert.Contains("MaximumTtl", failure.Message, StringComparison.Ordinal);
        Assert.Equal(0, cache.AdmissionAttempts);

        // After 23 hours it is still too early to fit the remaining validity.
        clock.Advance(TimeSpan.FromHours(23));
        await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
        Assert.Equal(0, cache.AdmissionAttempts);

        // Once it fits, a first use can succeed but subsequent uses cannot.
        clock.Advance(TimeSpan.FromHours(2));
        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<ReplayAttackException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
        Assert.Equal(2, cache.AdmissionAttempts);
    }

    [Fact]
    public async Task Should_PreserveFullExpirationAndSkewWindow_ForValidCredential()
    {
        var clock = new MutableClock(_fixedNow);
        var cache = new RetentionCache(clock);
        var options = new ReplayProtectionOptions { Enabled = true };
        var validator = new JtiValidator(cache, options, clock);
        var claims = Claims(_fixedNow.AddHours(2).ToUnixTimeSeconds());

        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        Assert.Equal(1, cache.AdmissionAttempts);
        Assert.True(cache.LastTtl.HasValue);
        Assert.Equal(TimeSpan.FromHours(2) + options.ClockSkewTolerance, cache.LastTtl.Value);

        clock.Advance(TimeSpan.FromHours(1));
        await Assert.ThrowsAsync<ReplayAttackException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
        Assert.Equal(2, cache.AdmissionAttempts);
    }

    [Fact]
    public async Task Should_AllowExactMaximumRetention_AndRejectAnyOvershoot()
    {
        var clock = new MutableClock(_fixedNow);
        var cache = new RetentionCache(clock);
        var options = new ReplayProtectionOptions
        {
            Enabled = true,
            MaximumTtl = TimeSpan.FromHours(1),
            ClockSkewTolerance = TimeSpan.FromSeconds(30)
        };
        var validator = new JtiValidator(cache, options, clock);

        await validator.ValidateAsync(
            Claims(_fixedNow.AddMinutes(59).AddSeconds(30).ToUnixTimeSeconds()),
            TestContext.Current.CancellationToken);

        Assert.True(cache.LastTtl.HasValue);
        Assert.Equal(options.MaximumTtl, cache.LastTtl.Value);
        await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(
                Claims(_fixedNow.AddMinutes(59).AddSeconds(31).ToUnixTimeSeconds(), "too-long"),
                TestContext.Current.CancellationToken));
        Assert.Equal(1, cache.AdmissionAttempts);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("\"2030-01-01\"")]
    [InlineData("1.5")]
    [InlineData("9223372036854775807")]
    public async Task Should_RejectMalformedExpiration_WithoutTouchingReplayCache(string expirationJson)
    {
        var clock = new MutableClock(_fixedNow);
        var cache = new RetentionCache(clock);
        var validator = new JtiValidator(cache, new ReplayProtectionOptions { Enabled = true }, clock);
        var claims = Claims(null);
        claims["exp"] = JsonSerializer.Deserialize<JsonElement>(expirationJson);

        await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

        Assert.Equal(0, cache.AdmissionAttempts);
    }

    [Fact]
    public async Task Should_RejectMissingExpiration_WithoutTouchingReplayCache()
    {
        var clock = new MutableClock(_fixedNow);
        var cache = new RetentionCache(clock);
        var validator = new JtiValidator(cache, new ReplayProtectionOptions { Enabled = true }, clock);

        await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(Claims(null), TestContext.Current.CancellationToken));

        Assert.Equal(0, cache.AdmissionAttempts);
    }

    private static Dictionary<string, JsonElement> Claims(long? expiry, string jti = "replay-test")
    {
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement("https://issuer.example.test"),
            ["jti"] = JsonSerializer.SerializeToElement(jti)
        };
        if (expiry is { } value)
        {
            claims["exp"] = JsonSerializer.SerializeToElement(value);
        }

        return claims;
    }

    private sealed class MutableClock(DateTimeOffset initial) : TimeProvider
    {
        private DateTimeOffset _now = initial;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }

    private sealed class RetentionCache(MutableClock clock) : IJtiCache
    {
        private readonly Dictionary<(string Issuer, string Jti), DateTimeOffset> _expirations = [];
        public int AdmissionAttempts { get; private set; }
        public TimeSpan? LastTtl { get; private set; }

        public Task<bool> TryAddAsync(string issuer, string jti, TimeSpan ttl, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AdmissionAttempts++;
            LastTtl = ttl;
            var key = (issuer, jti);
            if (_expirations.TryGetValue(key, out var expiration) && expiration > clock.GetUtcNow())
            {
                return Task.FromResult(false);
            }

            _expirations[key] = clock.GetUtcNow().Add(ttl);
            return Task.FromResult(true);
        }

        public Task<bool> ExistsAsync(string issuer, string jti, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_expirations.TryGetValue((issuer, jti), out var expiration) &&
                expiration > clock.GetUtcNow());
        }

        public Task RemoveAsync(string issuer, string jti, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _expirations.Remove((issuer, jti));
            return Task.CompletedTask;
        }
    }
}
