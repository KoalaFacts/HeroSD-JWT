using HeroSdJwt.Exceptions;
using HeroSdJwt.Verification.ReplayProtection;
using System.Text.Json;

namespace HeroSdJwt.Tests.Verification.ReplayProtection;

/// <summary>
/// Tests for JtiValidator.
/// These tests are currently in RED state (will fail until implementation exists).
/// </summary>
public class JtiValidatorTests
{
    private readonly IJtiCache cache;
    private readonly ReplayProtectionOptions options;
    private readonly JtiValidator validator;

    public JtiValidatorTests()
    {
        options = new ReplayProtectionOptions
        {
            Enabled = true,
            RequireJtiClaim = true,
            DefaultTtl = TimeSpan.FromHours(1),
            MaximumTtl = TimeSpan.FromHours(24),
            ClockSkewTolerance = TimeSpan.FromSeconds(30),
            FailureMode = CacheFailureMode.FailClosed
        };
        cache = new InMemoryJtiCache(options);
        validator = new JtiValidator(cache, options);
    }

    [Fact]
    public async Task ValidateAsync_FirstTime_Succeeds()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer),
            ["jti"] = JsonSerializer.SerializeToElement(jti),
            ["exp"] = JsonSerializer.SerializeToElement(exp)
        };

        // Act & Assert - Should not throw
        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task ValidateAsync_SecondTime_ThrowsReplayAttackException()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer),
            ["jti"] = JsonSerializer.SerializeToElement(jti),
            ["exp"] = JsonSerializer.SerializeToElement(exp)
        };

        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        // Act & Assert - Second validation should throw
        var ex = await Assert.ThrowsAsync<ReplayAttackException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

        Assert.Equal(jti, ex.Jti);
        Assert.Equal(issuer, ex.Issuer);
    }

    [Fact]
    public async Task ValidateAsync_MissingJtiWithRequireTrue_ThrowsSdJwtException()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer)
            // No jti claim
        };

        // Act & Assert
        var ex = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

        Assert.Contains("jti", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_MissingJtiWithRequireFalse_Succeeds()
    {
        // Arrange
        var permissiveOptions = new ReplayProtectionOptions
        {
            Enabled = true,
            RequireJtiClaim = false // Allow missing jti
        };
        var permissiveValidator = new JtiValidator(cache, permissiveOptions);

        var issuer = "https://issuer.example";
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer)
            // No jti claim
        };

        // Act & Assert - Should not throw (jti not required)
        await permissiveValidator.ValidateAsync(claims, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task ValidateAsync_MissingIssuer_ThrowsSdJwtException()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();
        var claims = new Dictionary<string, JsonElement>
        {
            ["jti"] = JsonSerializer.SerializeToElement(jti)
            // No issuer claim
        };

        // Act & Assert
        var ex = await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

        Assert.Contains("iss", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_WithExp_CalculatesTtlCorrectly()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var exp = DateTimeOffset.UtcNow.AddHours(2).ToUnixTimeSeconds();
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer),
            ["jti"] = JsonSerializer.SerializeToElement(jti),
            ["exp"] = JsonSerializer.SerializeToElement(exp)
        };

        // Act
        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        // Assert - Entry should exist in cache
        var exists = await cache.ExistsAsync(issuer, jti, TestContext.Current.CancellationToken);
        Assert.True(exists);
    }

    [Fact]
    public async Task ValidateAsync_WithoutExp_UsesDefaultTtl()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer),
            ["jti"] = JsonSerializer.SerializeToElement(jti)
            // No exp claim - should use DefaultTtl
        };

        // Act
        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        // Assert - Entry should exist in cache
        var exists = await cache.ExistsAsync(issuer, jti, TestContext.Current.CancellationToken);
        Assert.True(exists);
    }

    [Fact]
    public async Task ValidateAsync_ExpiredToken_ThrowsSdJwtException()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var exp = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds(); // Already expired
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer),
            ["jti"] = JsonSerializer.SerializeToElement(jti),
            ["exp"] = JsonSerializer.SerializeToElement(exp)
        };

        // Act & Assert - Should throw due to expiration
        await Assert.ThrowsAsync<SdJwtException>(() =>
            validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ValidateAsync_VeryLongExp_CapsTtlAtMaximum()
    {
        // Arrange
        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var exp = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds(); // Way beyond MaximumTtl
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer),
            ["jti"] = JsonSerializer.SerializeToElement(jti),
            ["exp"] = JsonSerializer.SerializeToElement(exp)
        };

        // Act - Should cap TTL at MaximumTtl (24 hours)
        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        // Assert - Entry exists (capped TTL used)
        var exists = await cache.ExistsAsync(issuer, jti, TestContext.Current.CancellationToken);
        Assert.True(exists);
    }

    [Fact]
    public async Task ValidateAsync_DifferentIssuers_SameJti_BothSucceed()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();
        var issuer1 = "https://issuer1.example";
        var issuer2 = "https://issuer2.example";
        var exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();

        var claims1 = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer1),
            ["jti"] = JsonSerializer.SerializeToElement(jti),
            ["exp"] = JsonSerializer.SerializeToElement(exp)
        };

        var claims2 = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer2),
            ["jti"] = JsonSerializer.SerializeToElement(jti),
            ["exp"] = JsonSerializer.SerializeToElement(exp)
        };

        // Act & Assert - Both should succeed (different cache keys)
        await validator.ValidateAsync(claims1, TestContext.Current.CancellationToken);
        await validator.ValidateAsync(claims2, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task ValidateAsync_DisabledReplayProtection_AlwaysSucceeds()
    {
        // Arrange
        var disabledOptions = new ReplayProtectionOptions { Enabled = false };
        var disabledValidator = new JtiValidator(cache, disabledOptions);

        var issuer = "https://issuer.example";
        var jti = Guid.NewGuid().ToString();
        var exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement(issuer),
            ["jti"] = JsonSerializer.SerializeToElement(jti),
            ["exp"] = JsonSerializer.SerializeToElement(exp)
        };

        // Act - Verify twice with disabled replay protection
        await disabledValidator.ValidateAsync(claims, TestContext.Current.CancellationToken);
        await disabledValidator.ValidateAsync(claims, TestContext.Current.CancellationToken); // Should not throw

        // Assert - Both succeed (no exception thrown)
        Assert.True(true);
    }
}
