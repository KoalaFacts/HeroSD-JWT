using HeroSdJwt.AspNetCore.Authentication;
using HeroSdJwt.Verification;
using HeroSdJwt.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HeroSdJwt.AspNetCore.Tests.Unit;

/// <summary>
/// Tests for <see cref="SdJwtAuthenticationBuilderExtensions"/>.
/// Verifies authentication scheme registration and configuration.
/// </summary>
public class AuthenticationBuilderExtensionsTests
{
    [Fact]
    public async Task AddSdJwt_RegistersAuthenticationHandler()
    {
        // Arrange
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();

        // Act
        authBuilder.AddSdJwt(options =>
        {
            options.FallbackKey = new byte[32]; // Dummy key
        });

        var serviceProvider = services.BuildServiceProvider();

        // Assert - Authentication handler should be registered
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        var scheme = await schemeProvider.GetSchemeAsync(SdJwtAuthenticationDefaults.AUTHENTICATION_SCHEME);

        Assert.NotNull(scheme);
        Assert.Equal(SdJwtAuthenticationDefaults.AUTHENTICATION_SCHEME, scheme.Name);
        Assert.Equal(typeof(SdJwtAuthenticationHandler), scheme.HandlerType);
    }

    [Fact]
    public void AddSdJwt_AutomaticallyRegistersSdJwtServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();

        // Act - AddSdJwt should automatically call AddSdJwtServices
        authBuilder.AddSdJwt(options =>
        {
            options.FallbackKey = new byte[32];
        });

        var serviceProvider = services.BuildServiceProvider();

        // Assert - Core SD-JWT services should be available
        Assert.NotNull(serviceProvider.GetService<ISdJwtVerifier>());
    }

    [Fact]
    public async Task AddSdJwt_UsesDefaultSchemeWhenNotSpecified()
    {
        // Arrange
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();

        // Act
        authBuilder.AddSdJwt(options =>
        {
            options.FallbackKey = new byte[32];
        });

        var serviceProvider = services.BuildServiceProvider();
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();

        // Assert
        var scheme = await schemeProvider.GetSchemeAsync(SdJwtAuthenticationDefaults.AUTHENTICATION_SCHEME);
        Assert.NotNull(scheme);
        Assert.Equal("SdJwt", scheme?.Name);
    }

    [Fact]
    public async Task AddSdJwt_AllowsCustomSchemeName()
    {
        // Arrange
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();
        var customScheme = "CustomSdJwt";

        // Act
        authBuilder.AddSdJwt(customScheme, options =>
        {
            options.FallbackKey = new byte[32];
        });

        var serviceProvider = services.BuildServiceProvider();
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();

        // Assert
        var scheme = await schemeProvider.GetSchemeAsync(customScheme);
        Assert.NotNull(scheme);
        Assert.Equal(customScheme, scheme?.Name);
    }

    [Fact]
    public void AddSdJwt_ConfiguresOptions()
    {
        // Arrange
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();
        var testKey = new byte[32];

        // Act
        authBuilder.AddSdJwt(options =>
        {
            options.FallbackKey = testKey;
            options.VerificationOptions = new SdJwtVerificationOptions
            {
                ClockSkew = TimeSpan.FromMinutes(3), // Within valid range (< 5 minutes)
                RequireKeyBinding = true,
                ExpectedAudience = "https://api.example.com",
                ExpectedNonce = "test-nonce",
                ExpectedKeyType = VerificationKeyType.Symmetric
            };
        });

        var serviceProvider = services.BuildServiceProvider();
        var optionsMonitor = serviceProvider.GetRequiredService<IOptionsMonitor<SdJwtAuthenticationOptions>>();

        // Assert
        var options = optionsMonitor.Get(SdJwtAuthenticationDefaults.AUTHENTICATION_SCHEME);
        Assert.Same(testKey, options.FallbackKey);
        Assert.Equal(TimeSpan.FromMinutes(3), options.VerificationOptions.ClockSkew);
        Assert.True(options.VerificationOptions.RequireKeyBinding);
    }

    [Fact]
    public async Task AddSdJwt_WithoutConfiguration_UsesDefaults()
    {
        // Arrange
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();

        // Act
        authBuilder.AddSdJwt();

        var serviceProvider = services.BuildServiceProvider();
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();

        // Assert - Should register even without configuration
        var scheme = await schemeProvider.GetSchemeAsync(SdJwtAuthenticationDefaults.AUTHENTICATION_SCHEME);
        Assert.NotNull(scheme);
    }

    [Fact]
    public async Task AddSdJwt_WithCustomDisplayName_SetsDisplayName()
    {
        // Arrange
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();
        var customDisplayName = "My Custom SD-JWT";

        // Act
        authBuilder.AddSdJwt("SdJwt", customDisplayName, options =>
        {
            options.FallbackKey = new byte[32];
        });

        var serviceProvider = services.BuildServiceProvider();
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();

        // Assert
        var scheme = await schemeProvider.GetSchemeAsync("SdJwt");
        Assert.Equal(customDisplayName, scheme?.DisplayName);
    }
}
