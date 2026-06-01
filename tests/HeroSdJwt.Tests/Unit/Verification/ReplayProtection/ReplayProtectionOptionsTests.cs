using HeroSdJwt.Verification.ReplayProtection;

namespace HeroSdJwt.Tests.Unit.Verification.ReplayProtection;

/// <summary>
/// Validation tests for <see cref="ReplayProtectionOptions"/>.
/// Covers every guard clause in <see cref="ReplayProtectionOptions.Validate"/> so that
/// misconfiguration fails fast instead of silently weakening replay protection.
/// </summary>
public class ReplayProtectionOptionsTests
{
    [Fact]
    public void Validate_WithDefaults_DoesNotThrow()
    {
        var options = new ReplayProtectionOptions();

        var exception = Record.Exception(options.Validate);

        Assert.Null(exception);
    }

    [Fact]
    public void Defaults_AreSecureByDefault()
    {
        var options = new ReplayProtectionOptions();

        Assert.False(options.Enabled);
        Assert.Equal(CacheFailureMode.FailClosed, options.FailureMode);
        Assert.True(options.RequireJtiClaim);
        Assert.Equal(1_000_000, options.MaxCacheEntries);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-1000)]
    public void Validate_WithNonPositiveMaxCacheEntries_Throws(int maxEntries)
    {
        var options = new ReplayProtectionOptions { MaxCacheEntries = maxEntries };

        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("MaxCacheEntries", ex.Message);
    }

    [Fact]
    public void Validate_WithExcessiveMaxCacheEntries_Throws()
    {
        var options = new ReplayProtectionOptions { MaxCacheEntries = 100_000_001 };

        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("100,000,000", ex.Message);
    }

    [Fact]
    public void Validate_AtMaxCacheEntriesUpperBound_DoesNotThrow()
    {
        var options = new ReplayProtectionOptions { MaxCacheEntries = 100_000_000 };

        Assert.Null(Record.Exception(options.Validate));
    }

    [Fact]
    public void Validate_WithNonPositiveDefaultTtl_Throws()
    {
        var options = new ReplayProtectionOptions { DefaultTtl = TimeSpan.Zero };

        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("DefaultTtl", ex.Message);
    }

    [Fact]
    public void Validate_WithNonPositiveMaximumTtl_Throws()
    {
        var options = new ReplayProtectionOptions
        {
            DefaultTtl = TimeSpan.FromMinutes(1),
            MaximumTtl = TimeSpan.Zero
        };

        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("MaximumTtl", ex.Message);
    }

    [Fact]
    public void Validate_WhenDefaultTtlExceedsMaximumTtl_Throws()
    {
        var options = new ReplayProtectionOptions
        {
            DefaultTtl = TimeSpan.FromHours(2),
            MaximumTtl = TimeSpan.FromHours(1)
        };

        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("less than or equal", ex.Message);
    }

    [Fact]
    public void Validate_WithNegativeClockSkewTolerance_Throws()
    {
        var options = new ReplayProtectionOptions { ClockSkewTolerance = TimeSpan.FromSeconds(-1) };

        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("ClockSkewTolerance", ex.Message);
    }

    [Fact]
    public void Validate_WithExcessiveClockSkewTolerance_Throws()
    {
        var options = new ReplayProtectionOptions { ClockSkewTolerance = TimeSpan.FromMinutes(6) };

        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("5 minutes", ex.Message);
    }

    [Fact]
    public void Validate_AtClockSkewToleranceUpperBound_DoesNotThrow()
    {
        var options = new ReplayProtectionOptions { ClockSkewTolerance = TimeSpan.FromMinutes(5) };

        Assert.Null(Record.Exception(options.Validate));
    }
}
