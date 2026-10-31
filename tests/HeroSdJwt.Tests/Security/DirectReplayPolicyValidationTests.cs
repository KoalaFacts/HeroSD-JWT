using HeroSdJwt.Verification.ReplayProtection;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A public JtiValidator using a custom atomic cache must enforce the same
/// replay-retention policy as the built-in InMemoryJtiCache.
/// </summary>
public sealed class DirectReplayPolicyValidationTests
{
    [Theory]
    [InlineData("excessive-skew")]
    [InlineData("negative-skew")]
    [InlineData("zero-retention")]
    [InlineData("shorter-than-default")]
    [InlineData("zero-capacity")]
    public void Should_RejectInvalidReplayPolicy_WhenCacheDoesNotValidateOptions(string invalidSetting)
    {
        var options = new ReplayProtectionOptions { Enabled = true };
        switch (invalidSetting)
        {
            case "excessive-skew":
                options.ClockSkewTolerance = TimeSpan.FromMinutes(6);
                break;
            case "negative-skew":
                options.ClockSkewTolerance = TimeSpan.FromTicks(-1);
                break;
            case "zero-retention":
                options.MaximumTtl = TimeSpan.Zero;
                break;
            case "shorter-than-default":
                options.MaximumTtl = TimeSpan.FromMinutes(30);
                break;
            case "zero-capacity":
                options.MaxCacheEntries = 0;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(invalidSetting));
        }

        // Unlike InMemoryJtiCache, an injected provider need not inspect
        // options. Direct use of JtiValidator must not bypass policy validation.
        Assert.Throws<InvalidOperationException>(() => new JtiValidator(new AcceptingCache(), options));
    }

    [Fact]
    public void Should_AcceptValidReplayPolicy_WithCustomCache()
    {
        var options = new ReplayProtectionOptions
        {
            Enabled = true,
            ClockSkewTolerance = TimeSpan.FromMinutes(5)
        };

        var validator = new JtiValidator(new AcceptingCache(), options);

        Assert.NotNull(validator);
    }

    private sealed class AcceptingCache : IJtiCache
    {
        public Task<bool> TryAddAsync(
            string issuer,
            string jti,
            TimeSpan ttl,
            CancellationToken cancellationToken = default) => Task.FromResult(true);

        public Task<bool> ExistsAsync(
            string issuer,
            string jti,
            CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task RemoveAsync(
            string issuer,
            string jti,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
