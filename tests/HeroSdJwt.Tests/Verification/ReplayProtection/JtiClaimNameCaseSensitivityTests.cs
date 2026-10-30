using HeroSdJwt.Exceptions;
using HeroSdJwt.Verification.ReplayProtection;
using System.Text.Json;

namespace HeroSdJwt.Tests.Verification.ReplayProtection;

/// <summary>
/// RFC 7519 registered claim names are case-sensitive even if a caller supplies
/// a dictionary with a case-insensitive comparer to the standalone replay API.
/// </summary>
public class JtiClaimNameCaseSensitivityTests
{
    [Theory]
    [InlineData("ISS", "jti", "exp", "iss")]
    [InlineData("iss", "JTI", "exp", "jti")]
    [InlineData("iss", "jti", "EXP", "exp")]
    public async Task Should_RejectNonCanonicalClaimNameWithoutAdmittingReplayMarker(
        string issuerName, string jwtIdName, string expirationName, string missingClaim)
    {
        var options = new ReplayProtectionOptions { Enabled = true, RequireJtiClaim = true };
        using var cache = new InMemoryJtiCache(options);
        var validator = new JtiValidator(cache, options);
        var claims = CreateClaims(issuerName, jwtIdName, expirationName);
        var cancellationToken = TestContext.Current.CancellationToken;

        var exception = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, cancellationToken));

        Assert.Contains(missingClaim, exception.Message, StringComparison.Ordinal);
        Assert.False(await cache.ExistsAsync("https://issuer.example", "replay-id", cancellationToken));
    }

    [Fact]
    public async Task Should_AllowCanonicalNamesInCaseInsensitiveDictionaryAndDetectReplay()
    {
        var options = new ReplayProtectionOptions { Enabled = true, RequireJtiClaim = true };
        using var cache = new InMemoryJtiCache(options);
        var validator = new JtiValidator(cache, options);
        var claims = CreateClaims("iss", "jti", "exp");
        var cancellationToken = TestContext.Current.CancellationToken;

        await validator.ValidateAsync(claims, cancellationToken);

        Assert.True(await cache.ExistsAsync("https://issuer.example", "replay-id", cancellationToken));
        _ = await Assert.ThrowsAsync<ReplayAttackException>(() =>
            validator.ValidateAsync(claims, cancellationToken));
    }

    private static Dictionary<string, JsonElement> CreateClaims(
        string issuerName, string jwtIdName, string expirationName) =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            [issuerName] = JsonSerializer.SerializeToElement("https://issuer.example"),
            [jwtIdName] = JsonSerializer.SerializeToElement("replay-id"),
            [expirationName] = JsonSerializer.SerializeToElement(
                DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds())
        };
}
