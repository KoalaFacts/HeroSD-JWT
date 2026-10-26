using HeroSdJwt.Exceptions;
using HeroSdJwt.Verification.ReplayProtection;
using System.Text.Json;

namespace HeroSdJwt.Tests.Verification.ReplayProtection;

/// <summary>
/// RFC 7519 NumericDate interoperability and replay-marker retention boundaries.
/// The issuer and claim verifier accept fractional seconds, so replay protection
/// must apply the same parsing rules without shortening a live marker.
/// </summary>
public class JtiFractionalExpirationTests
{
    private const string Issuer = "https://issuer.example";
    private const string Jti = "fractional-jti";
    private static readonly DateTimeOffset _start = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

    [Theory]
    [InlineData("1700000001.25")]
    [InlineData("1.70000000125e9")]
    public async Task Should_AdmitFractionalExpirationAndRetainReplayMarkerUntilExpiry(string numericDate)
    {
        var options = CreateOptions();
        var clock = new ManualTimeProvider(_start);
        using var cache = new InMemoryJtiCache(options, clock);
        var validator = new JtiValidator(cache, options, clock);
        var claims = CreateClaims(numericDate);

        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);
        _ = await Assert.ThrowsAsync<ReplayAttackException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

        clock.UtcNow = _start.AddSeconds(1).AddTicks(2_499_999);
        Assert.True(await cache.ExistsAsync(Issuer, Jti, TestContext.Current.CancellationToken));

        clock.UtcNow = _start.AddSeconds(1).AddTicks(2_500_000);
        Assert.False(await cache.ExistsAsync(Issuer, Jti, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Should_RoundSubTickFractionUpToKeepReplayMarkerLive()
    {
        var options = CreateOptions();
        var clock = new ManualTimeProvider(_start);
        using var cache = new InMemoryJtiCache(options, clock);
        var validator = new JtiValidator(cache, options, clock);
        var claims = CreateClaims("1700000001.00000001");

        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        // One hundredth of a microsecond is a tenth of a DateTime tick.
        // Rounding down would release the marker while the credential is valid.
        clock.UtcNow = _start.AddSeconds(1);
        Assert.True(await cache.ExistsAsync(Issuer, Jti, TestContext.Current.CancellationToken));

        clock.UtcNow = _start.AddSeconds(1).AddTicks(1);
        Assert.False(await cache.ExistsAsync(Issuer, Jti, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Should_RejectFractionalExpirationBeyondMaximumTtlBeforeCacheAdmission()
    {
        var options = CreateOptions();
        var clock = new ManualTimeProvider(_start);
        using var cache = new InMemoryJtiCache(options, clock);
        var validator = new JtiValidator(cache, options, clock);
        var claims = CreateClaims("1700003600.00000001");

        var exception = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

        Assert.Contains("MaximumTtl", exception.Message, StringComparison.Ordinal);
        Assert.False(await cache.ExistsAsync(Issuer, Jti, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("1700000000")]
    [InlineData("1700000000.0")]
    [InlineData("1e400")]
    [InlineData("253402300800.1")]
    [InlineData("-62135596800.1")]
    [InlineData("\"1700000001.25\"")]
    [InlineData("true")]
    public async Task Should_RejectExpiredOrInvalidNumericDateBeforeCacheAdmission(string numericDate)
    {
        var options = CreateOptions();
        var clock = new ManualTimeProvider(_start);
        using var cache = new InMemoryJtiCache(options, clock);
        var validator = new JtiValidator(cache, options, clock);
        var claims = CreateClaims(numericDate);

        _ = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

        Assert.False(await cache.ExistsAsync(Issuer, Jti, TestContext.Current.CancellationToken));
    }

    private static ReplayProtectionOptions CreateOptions() => new()
    {
        Enabled = true,
        RequireJtiClaim = true,
        ClockSkewTolerance = TimeSpan.Zero,
        MaximumTtl = TimeSpan.FromHours(1),
        DefaultTtl = TimeSpan.FromMinutes(1)
    };

    private static Dictionary<string, JsonElement> CreateClaims(string numericDate)
    {
        using var document = JsonDocument.Parse(numericDate);
        return new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(Issuer),
            ["jti"] = JsonSerializer.SerializeToElement(Jti),
            ["exp"] = document.RootElement.Clone()
        };
    }

    private sealed class ManualTimeProvider(DateTimeOffset initialUtcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = initialUtcNow;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
