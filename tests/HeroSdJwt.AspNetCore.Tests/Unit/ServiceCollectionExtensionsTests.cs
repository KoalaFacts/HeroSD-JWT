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
        services.AddSdJwtServices();
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
        services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var verifier = serviceProvider.GetService<ISdJwtVerifier>();
        Assert.NotNull(verifier);
        Assert.IsType<SdJwtVerifier>(verifier);
    }

    [Fact]
    public void AddSdJwtServices_RegistersIssuer()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var issuer = serviceProvider.GetService<ISdJwtIssuer>();
        Assert.NotNull(issuer);
        Assert.IsType<SdJwtIssuer>(issuer);
    }

    [Fact]
    public void AddSdJwtServices_RegistersPresenter()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var presenter = serviceProvider.GetService<ISdJwtPresenter>();
        Assert.NotNull(presenter);
        Assert.IsType<SdJwtPresenter>(presenter);
    }

    [Fact]
    public void AddSdJwtServices_RegistersIssuanceServices()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddSdJwtServices();
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
        services.AddSdJwtServices();
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
        services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var keyGenerator = serviceProvider.GetService<IKeyGenerator>();
        Assert.NotNull(keyGenerator);
        Assert.IsType<KeyGenerator>(keyGenerator);
    }

    [Fact]
    public void AddSdJwtServices_ServicesAreRegisteredAsSingletons()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        // Assert - Services should be singletons (same instance returned)
        var verifier1 = serviceProvider.GetService<ISdJwtVerifier>();
        var verifier2 = serviceProvider.GetService<ISdJwtVerifier>();
        Assert.Same(verifier1, verifier2);

        var issuer1 = serviceProvider.GetService<ISdJwtIssuer>();
        var issuer2 = serviceProvider.GetService<ISdJwtIssuer>();
        Assert.Same(issuer1, issuer2);
    }

    [Fact]
    public void AddSdJwtServices_CanBeCalledMultipleTimes()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act - Should not throw when called multiple times
        services.AddSdJwtServices();
        services.AddSdJwtServices();
        services.AddSdJwtServices();

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
        Assert.Throws<ArgumentNullException>(() => services!.AddSdJwtServices());
    }
}
