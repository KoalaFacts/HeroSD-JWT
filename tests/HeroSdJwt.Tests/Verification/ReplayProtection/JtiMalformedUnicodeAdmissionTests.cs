using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification.ReplayProtection;
using System.Text.Json;

namespace HeroSdJwt.Tests.Verification.ReplayProtection;

/// <summary>
/// The standalone replay validator must reject malformed registered JSON strings
/// with a domain error before consulting or mutating the replay cache.
/// </summary>
public sealed class JtiMalformedUnicodeAdmissionTests
{
    [Theory]
    [InlineData("iss", @"\uD800")]
    [InlineData("iss", @"\uDC00")]
    [InlineData("jti", @"\uD800")]
    [InlineData("jti", @"\uDC00")]
    public async Task Should_RejectMalformedRegisteredStrings_WithoutAdmittingMarker(
        string claimName, string escapedSurrogate)
    {
        var options = new ReplayProtectionOptions { Enabled = true, RequireJtiClaim = true };
        using var cache = new InMemoryJtiCache(options);
        var validator = new JtiValidator(cache, options);

        using var malformedJson = JsonDocument.Parse("\"" + escapedSurrogate + "\"");
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement("https://issuer.example"),
            ["jti"] = JsonSerializer.SerializeToElement("valid-replay-id"),
            ["exp"] = JsonSerializer.SerializeToElement(
                DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds())
        };
        claims[claimName] = malformedJson.RootElement.Clone();

        var exception = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
        Assert.False(await cache.ExistsAsync(
            "https://issuer.example", "valid-replay-id", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Should_AllowValidNonAsciiIssuerAndJwtId_AndStillDetectReplay()
    {
        const string issuer = "https://issuer.example/雪";
        const string jwtId = "replay-🙏-id";
        var options = new ReplayProtectionOptions { Enabled = true, RequireJtiClaim = true };
        using var cache = new InMemoryJtiCache(options);
        var validator = new JtiValidator(cache, options);
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer),
            ["jti"] = JsonSerializer.SerializeToElement(jwtId),
            ["exp"] = JsonSerializer.SerializeToElement(
                DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds())
        };

        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);
        Assert.True(await cache.ExistsAsync(issuer, jwtId, TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ReplayAttackException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
    }
}
