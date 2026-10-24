using System.Text.Json;
using HeroSdJwt.AspNetCore.Verification.ReplayProtection;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Verification.ReplayProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HeroSdJwt.Tests.Unit.Verification.ReplayProtection;

public class DistributedReplayRegistrationTests
{
    [Fact]
    public void Constructor_OrdinaryDistributedCache_RejectsUnsafeBackend()
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

        Assert.Throws<NotSupportedException>(() => new DistributedJtiCache(cache));
    }

    [Fact]
    public void Registration_OrdinaryDistributedCache_FailsClosedOnResolution()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddSdJwtDistributedReplayProtection();
        using var provider = services.BuildServiceProvider();

        Assert.Throws<NotSupportedException>(provider.GetRequiredService<IJtiCache>);
    }

    [Fact]
    public async Task Registration_EnablesValidator_AndPreservesExplicitCache()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IJtiCache>(new InMemoryJtiCache(new ReplayProtectionOptions()));
        services.AddSdJwtDistributedReplayProtection();
        using var provider = services.BuildServiceProvider();
        var validator = provider.GetRequiredService<JtiValidator>();
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement("issuer"),
            ["jti"] = JsonSerializer.SerializeToElement("registered-jti")
        };

        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<ReplayAttackException>(() => validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Registration_PreservesExplicitOptionsAndValidator()
    {
        var options = new ReplayProtectionOptions { Enabled = false };
        using var cache = new InMemoryJtiCache(options);
        var validator = new JtiValidator(cache, options);
        var services = new ServiceCollection();
        services.AddSingleton(options);
        services.AddSingleton(validator);
        services.AddSdJwtDistributedReplayProtection();
        using var provider = services.BuildServiceProvider();

        Assert.Same(options, provider.GetRequiredService<ReplayProtectionOptions>());
        Assert.Same(validator, provider.GetRequiredService<JtiValidator>());
        await provider.GetRequiredService<JtiValidator>().ValidateAsync([], TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Registration_ScopedAtomicBackend_ResolvesWithoutCaptiveDependencies()
    {
        var services = new ServiceCollection();
        services.AddScoped<IDistributedCache>(_ => new AtomicCacheFixture());
        services.AddSdJwtDistributedReplayProtection();
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        using var scope = provider.CreateScope();
        var validator = scope.ServiceProvider.GetRequiredService<JtiValidator>();
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement("issuer"),
            ["jti"] = JsonSerializer.SerializeToElement("scoped-jti")
        };

        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<ReplayAttackException>(() => validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Registration_ScopedCustomCache_ResolvesWithoutCaptiveDependencies()
    {
        var services = new ServiceCollection();
        services.AddScoped<IJtiCache>(_ => new InMemoryJtiCache(new ReplayProtectionOptions()));
        services.AddSdJwtDistributedReplayProtection();
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        using var scope = provider.CreateScope();
        var validator = scope.ServiceProvider.GetRequiredService<JtiValidator>();
        var claims = new Dictionary<string, JsonElement>
        {
            ["iss"] = JsonSerializer.SerializeToElement("issuer"),
            ["jti"] = JsonSerializer.SerializeToElement("custom-scoped-jti")
        };

        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<ReplayAttackException>(() => validator.ValidateAsync(claims, TestContext.Current.CancellationToken));
    }

}
