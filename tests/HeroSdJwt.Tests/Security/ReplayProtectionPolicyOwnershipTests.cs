using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification.ReplayProtection;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A configured replay validator must not inherit later changes to caller-owned
/// options that can weaken single-use admission or marker retention.
/// </summary>
public class ReplayProtectionPolicyOwnershipTests
{
    [Fact]
    public async Task Should_RejectReplay_WhenSourceOptionsDisableProtection()
    {
        var options = new ReplayProtectionOptions { Enabled = true };
        using var cache = new InMemoryJtiCache(options);
        var validator = new JtiValidator(cache, options);
        var claims = Claims("same-jti");
        var cancellationToken = TestContext.Current.CancellationToken;

        await validator.ValidateAsync(claims, cancellationToken);

        // A caller retaining the mutable options must not disable an already
        // configured verifier after the first token has been admitted.
        options.Enabled = false;

        await Assert.ThrowsAsync<ReplayAttackException>(() =>
            validator.ValidateAsync(claims, cancellationToken));
    }

    [Fact]
    public async Task Should_KeepRequiredJti_WhenSourceOptionsRemoveRequirement()
    {
        var options = new ReplayProtectionOptions { Enabled = true, RequireJtiClaim = true };
        using var cache = new InMemoryJtiCache(options);
        var validator = new JtiValidator(cache, options);
        var claims = Claims(jti: null);

        options.RequireJtiClaim = false;

        var exception = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.MissingRequiredClaim, exception.ErrorCode);
    }

    [Fact]
    public async Task Should_KeepMaximumRetention_WhenSourceOptionsIncreaseLimit()
    {
        var options = new ReplayProtectionOptions
        {
            Enabled = true,
            DefaultTtl = TimeSpan.FromMinutes(30),
            MaximumTtl = TimeSpan.FromMinutes(30)
        };
        using var cache = new InMemoryJtiCache(options);
        var validator = new JtiValidator(cache, options);
        var claims = Claims("long-lived-jti", DateTimeOffset.UtcNow.AddHours(1));

        options.MaximumTtl = TimeSpan.FromHours(24);

        var exception = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
        Assert.Contains("MaximumTtl", exception.Message, StringComparison.Ordinal);
    }

    private static Dictionary<string, JsonElement> Claims(string? jti, DateTimeOffset? expiry = null)
    {
        var result = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement("https://issuer.example.test"),
            ["exp"] = JsonSerializer.SerializeToElement((expiry ?? DateTimeOffset.UtcNow.AddMinutes(10)).ToUnixTimeSeconds())
        };

        if (jti is not null)
        {
            result["jti"] = JsonSerializer.SerializeToElement(jti);
        }

        return result;
    }
}
