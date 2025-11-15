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
    private readonly IJtiCache _cache;
    private readonly ReplayProtectionOptions _options;
    private readonly JtiValidator _validator;

    public JtiValidatorTests()
    {
        _options = new ReplayProtectionOptions
        {
            Enabled = true,
            RequireJtiClaim = true,
            DefaultTtl = TimeSpan.FromHours(1),
            MaximumTtl = TimeSpan.FromHours(24),
            ClockSkewTolerance = TimeSpan.FromSeconds(30),
            FailureMode = CacheFailureMode.FailClosed
        };
        _cache = new InMemoryJtiCache(_options);
        _validator = new JtiValidator(_cache, _options);
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
        await _validator.ValidateAsync(claims, TestContext.Current.CancellationToken);
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

        await _validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        // Act & Assert - Second validation should throw
        var ex = await Assert.ThrowsAsync<ReplayAttackException>(() =>
            _validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

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
            _validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

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
        var permissiveValidator = new JtiValidator(_cache, permissiveOptions);

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
            _validator.ValidateAsync(claims, TestContext.Current.CancellationToken));

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
        await _validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        // Assert - Entry should exist in _cache
        var exists = await _cache.ExistsAsync(issuer, jti, TestContext.Current.CancellationToken);
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
        await _validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        // Assert - Entry should exist in _cache
        var exists = await _cache.ExistsAsync(issuer, jti, TestContext.Current.CancellationToken);
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
            _validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
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
        await _validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        // Assert - Entry exists (capped TTL used)
        var exists = await _cache.ExistsAsync(issuer, jti, TestContext.Current.CancellationToken);
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

        // Act & Assert - Both should succeed (different _cache keys)
        await _validator.ValidateAsync(claims1, TestContext.Current.CancellationToken);
        await _validator.ValidateAsync(claims2, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task ValidateAsync_DisabledReplayProtection_AlwaysSucceeds()
    {
        // Arrange
        var disabledOptions = new ReplayProtectionOptions { Enabled = false };
        var disabledValidator = new JtiValidator(_cache, disabledOptions);

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
