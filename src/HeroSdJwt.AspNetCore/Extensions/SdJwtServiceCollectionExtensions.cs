using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;
using HeroSdJwt.Verification.Revocation;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection.Extensions;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130 // Namespace does not match folder structure

/// <summary>
/// Extension methods for setting up SD-JWT services in an <see cref="IServiceCollection" />.
/// </summary>
public static class SdJwtServiceCollectionExtensions
{
    /// <summary>
    /// Adds SD-JWT services to the specified <see cref="IServiceCollection" />.
    /// Registers all core SD-JWT components for dependency injection.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <remarks>
    /// This method registers the following services as singletons (all implementations are stateless and thread-safe):
    /// <list type="bullet">
    /// <item><description><see cref="ISdJwtVerifier"/> - Core verification service</description></item>
    /// <item><description><see cref="ISdJwtIssuer"/> - Core issuance service</description></item>
    /// <item><description><see cref="ISdJwtPresenter"/> - Presentation creation service</description></item>
    /// <item><description>All cryptographic and validation services</description></item>
    /// </list>
    /// </remarks>
    /// <example>
    /// <code>
    /// services.AddSdJwtServices();
    /// </code>
    /// </example>
    public static IServiceCollection AddSdJwtServices(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Register verification services (stateless, thread-safe - use singleton)
        services.TryAddSingleton<IEcPublicKeyConverter, EcPublicKeyConverter>();
        services.TryAddSingleton<ISignatureValidator, SignatureValidator>();
        services.TryAddSingleton<IDigestValidator, DigestValidator>();
        services.TryAddSingleton<IKeyBindingValidator, KeyBindingValidator>();
        services.TryAddSingleton<IClaimValidator, ClaimValidator>();

        // Register core verifiers (sync + async interface on same instance)
        services.TryAddSingleton<ISdJwtVerifier>(serviceProvider =>
        {
            // Default options - can be overridden by authentication configuration
            var options = new SdJwtVerificationOptions
            {
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            return new SdJwtVerifier(
                options,
                serviceProvider.GetRequiredService<IEcPublicKeyConverter>(),
                serviceProvider.GetRequiredService<ISignatureValidator>(),
                serviceProvider.GetRequiredService<IDigestValidator>(),
                serviceProvider.GetRequiredService<IKeyBindingValidator>(),
                serviceProvider.GetRequiredService<IClaimValidator>()
            );
        });
        services.TryAddSingleton<ISdJwtVerifierAsync>(sp =>
            (ISdJwtVerifierAsync)sp.GetRequiredService<ISdJwtVerifier>());

        // Register issuance services (for applications that need to issue SD-JWTs)
        services.TryAddSingleton<IDisclosureGenerator, DisclosureGenerator>();
        services.TryAddSingleton<IDigestCalculator, DigestCalculator>();
        services.TryAddSingleton<IJwtSigner, JwtSigner>();
        services.TryAddSingleton<IDecoyDigestGenerator, DecoyDigestGenerator>();

        // Register core issuer (depends on services above)
        services.TryAddSingleton<ISdJwtIssuer>(serviceProvider =>
        {
            return new SdJwtIssuer(
                serviceProvider.GetRequiredService<IDisclosureGenerator>(),
                serviceProvider.GetRequiredService<IDigestCalculator>(),
                serviceProvider.GetRequiredService<IEcPublicKeyConverter>(),
                serviceProvider.GetRequiredService<IJwtSigner>()
            );
        });

        // Register presentation services
        services.TryAddSingleton<IDisclosureClaimPathMapper, DisclosureClaimPathMapper>();
        services.TryAddSingleton<ISdJwtPresenter>(serviceProvider =>
        {
            return new SdJwtPresenter(
                serviceProvider.GetRequiredService<IDisclosureClaimPathMapper>()
            );
        });

        // Register key generation helper
        services.TryAddSingleton<IKeyGenerator, KeyGenerator>();

        return services;
    }

    /// <summary>
    /// Adds distributed replay protection using the configured <see cref="IDistributedCache"/>.
    /// </summary>
    public static IServiceCollection AddSdJwtDistributedReplayProtection(this IServiceCollection services, string keyPrefix = "sdjwt:jti")
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<IJtiCache>(sp => new DistributedJtiCache(
            sp.GetRequiredService<IDistributedCache>(),
            keyPrefix));
        return services;
    }

    /// <summary>
    /// Adds distributed revocation store using the configured <see cref="IDistributedCache"/>.
    /// </summary>
    public static IServiceCollection AddSdJwtDistributedRevocation(this IServiceCollection services, string keyPrefix = "sdjwt:revocation")
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<IRevocationStore>(sp => new DistributedRevocationStore(
            sp.GetRequiredService<IDistributedCache>(),
            keyPrefix));
        return services;
    }

}
