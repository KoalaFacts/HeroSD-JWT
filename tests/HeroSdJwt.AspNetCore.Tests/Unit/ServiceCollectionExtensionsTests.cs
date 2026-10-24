using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Verification;
using Microsoft.Extensions.DependencyInjection;

namespace HeroSdJwt.AspNetCore.Tests.Unit;

/// <summary>
/// Tests for <see cref="SdJwtServiceCollectionExtensions"/>.
/// Verifies that all required services are properly registered in the DI container.
/// </summary>
public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddSdJwtServices_RegistersAllRequiredVerificationServices()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        _ = services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert - All verification services should be registered
        Assert.NotNull(serviceProvider.GetService<IEcPublicKeyConverter>());
        Assert.NotNull(serviceProvider.GetService<ISignatureValidator>());
        Assert.NotNull(serviceProvider.GetService<IDigestValidator>());
        Assert.NotNull(serviceProvider.GetService<IKeyBindingValidator>());
        Assert.NotNull(serviceProvider.GetService<IClaimValidator>());
    }

    [Fact]
    public void AddSdJwtServices_RegistersVerifier()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        _ = services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var verifier = serviceProvider.GetService<ISdJwtVerifier>();
        Assert.NotNull(verifier);
        _ = Assert.IsType<SdJwtVerifier>(verifier);
    }

    [Fact]
    public void AddSdJwtServices_RegistersIssuer()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        _ = services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var issuer = serviceProvider.GetService<ISdJwtIssuer>();
        Assert.NotNull(issuer);
        _ = Assert.IsType<SdJwtIssuer>(issuer);
    }

    [Fact]
    public void AddSdJwtServices_RegistersPresenter()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        _ = services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var presenter = serviceProvider.GetService<ISdJwtPresenter>();
        Assert.NotNull(presenter);
        _ = Assert.IsType<SdJwtPresenter>(presenter);
    }

    [Fact]
    public void AddSdJwtServices_RegistersIssuanceServices()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        _ = services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert - All issuance services should be registered
        Assert.NotNull(serviceProvider.GetService<IDisclosureGenerator>());
        Assert.NotNull(serviceProvider.GetService<IDigestCalculator>());
        Assert.NotNull(serviceProvider.GetService<IJwtSigner>());
        Assert.NotNull(serviceProvider.GetService<IDecoyDigestGenerator>());
    }

    [Fact]
    public void AddSdJwtServices_RegistersPresentationServices()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        _ = services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        Assert.NotNull(serviceProvider.GetService<IDisclosureClaimPathMapper>());
    }

    [Fact]
    public void AddSdJwtServices_RegistersKeyGenerator()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        _ = services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var keyGenerator = serviceProvider.GetService<IKeyGenerator>();
        Assert.NotNull(keyGenerator);
        _ = Assert.IsType<KeyGenerator>(keyGenerator);
    }

    [Fact]
    public void AddSdJwtServices_VerifierIsScopedAndIssuerIsSingleton()
    {
        var services = new ServiceCollection();
        _ = services.AddSdJwtServices();
        using var serviceProvider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var first = serviceProvider.CreateScope();
        using var second = serviceProvider.CreateScope();

        var verifier = first.ServiceProvider.GetRequiredService<ISdJwtVerifier>();
        Assert.Same(verifier, first.ServiceProvider.GetRequiredService<ISdJwtVerifier>());
        Assert.Same(verifier, first.ServiceProvider.GetRequiredService<ISdJwtVerifierAsync>());
        Assert.NotSame(verifier, second.ServiceProvider.GetRequiredService<ISdJwtVerifier>());
        Assert.Same(first.ServiceProvider.GetRequiredService<ISdJwtIssuer>(), second.ServiceProvider.GetRequiredService<ISdJwtIssuer>());
    }

    [Fact]
    public void AddSdJwtServices_CanBeCalledMultipleTimes()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act - Should not throw when called multiple times
        _ = services.AddSdJwtServices();
        _ = services.AddSdJwtServices();
        _ = services.AddSdJwtServices();

        var serviceProvider = services.BuildServiceProvider();

        // Assert - Services should still be registered correctly
        Assert.NotNull(serviceProvider.GetService<ISdJwtVerifier>());
        Assert.NotNull(serviceProvider.GetService<ISdJwtIssuer>());
    }

    [Fact]
    public void AddSdJwtServices_ThrowsWhenServicesIsNull()
    {
        // Arrange
        ServiceCollection? services = null;

        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() => services!.AddSdJwtServices());
    }
}
