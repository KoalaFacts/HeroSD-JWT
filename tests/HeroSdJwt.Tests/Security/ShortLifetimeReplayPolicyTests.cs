using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification.ReplayProtection;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The legacy DefaultTtl is not used for replay admission; a shorter
/// MaximumTtl must still protect valid short-lived credentials atomically.
/// </summary>
public sealed class ShortLifetimeReplayPolicyTests
{
    [Fact]
    public async Task Should_ProtectShortLivedCredential_WhenMaximumTtlIsShorterThanLegacyDefault()
    {
        var options = new ReplayProtectionOptions
        {
            Enabled = true,
            MaximumTtl = TimeSpan.FromMinutes(15),
            ClockSkewTolerance = TimeSpan.Zero
            // DefaultTtl stays at its legacy one-hour default.
        };

        using var cache = new InMemoryJtiCache(options);
        var validator = new JtiValidator(cache, options);
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement("https://issuer.example"),
            ["jti"] = JsonSerializer.SerializeToElement(Guid.NewGuid().ToString("N")),
            ["exp"] = JsonSerializer.SerializeToElement(now.AddMinutes(5).ToUnixTimeSeconds())
        };

        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);
        _ = await Assert.ThrowsAsync<ReplayAttackException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

        // Relaxing the unused default must NOT relax MaximumTtl's fail-closed admission.
        claims["jti"] = JsonSerializer.SerializeToElement(Guid.NewGuid().ToString("N"));
        claims["exp"] = JsonSerializer.SerializeToElement(now.AddMinutes(30).ToUnixTimeSeconds());
        var error = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.InvalidInput, error.ErrorCode);
    }
}
