using HeroSdJwt.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.AspNetCore.Authentication;
#pragma warning restore IDE0130 // Namespace does not match folder structure

/// <summary>
/// Extension methods for adding SD-JWT authentication to an <see cref="AuthenticationBuilder"/>.
/// </summary>
public static class SdJwtAuthenticationBuilderExtensions
{
    /// <summary>
    /// Adds SD-JWT authentication to the authentication builder.
    /// This enables automatic verification of SD-JWT tokens from incoming requests.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <returns>The authentication builder for method chaining.</returns>
    /// <remarks>
    /// This method uses the default authentication scheme "SdJwt".
    /// Make sure to configure the options via appsettings.json or the configure delegate.
    /// </remarks>
    /// <example>
    /// <code>
    /// services.AddSdJwtServices()
    ///     .AddAuthentication()
    ///     .AddSdJwt(options =>
    ///     {
    ///         options.FallbackKey = Convert.FromBase64String(configuration["SdJwt:Key"]);
    ///         options.VerificationOptions = new SdJwtVerificationOptions
    ///         {
    ///             ClockSkew = TimeSpan.FromMinutes(5),
    ///             RequireKeyBinding = true
    ///         };
    ///     });
    /// </code>
    /// </example>
    public static AuthenticationBuilder AddSdJwt(
        this AuthenticationBuilder builder)
        => builder.AddSdJwt(SdJwtAuthenticationDefaults.AuthenticationScheme);

    /// <summary>
    /// Adds SD-JWT authentication to the authentication builder with a specific scheme name.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="authenticationScheme">The name of the authentication scheme.</param>
    /// <returns>The authentication builder for method chaining.</returns>
    public static AuthenticationBuilder AddSdJwt(
        this AuthenticationBuilder builder,
        string authenticationScheme)
        => builder.AddSdJwt(authenticationScheme, configureOptions: null);

    /// <summary>
    /// Adds SD-JWT authentication to the authentication builder with configuration.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configureOptions">Action to configure the authentication options.</param>
    /// <returns>The authentication builder for method chaining.</returns>
    /// <example>
    /// <code>
    /// services.AddAuthentication()
    ///     .AddSdJwt(options =>
    ///     {
    ///         options.KeyResolver = keyId => keyStore.GetKey(keyId);
    ///         options.FallbackKey = defaultKey;
    ///         options.VerificationOptions.ClockSkew = TimeSpan.FromMinutes(5);
    ///     });
    /// </code>
    /// </example>
    public static AuthenticationBuilder AddSdJwt(
        this AuthenticationBuilder builder,
        Action<SdJwtAuthenticationOptions>? configureOptions)
        => builder.AddSdJwt(SdJwtAuthenticationDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds SD-JWT authentication to the authentication builder with a custom scheme name and configuration.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="authenticationScheme">The name of the authentication scheme.</param>
    /// <param name="configureOptions">Action to configure the authentication options.</param>
    /// <returns>The authentication builder for method chaining.</returns>
    /// <remarks>
    /// This is the most flexible overload, allowing custom scheme names and full configuration.
    /// </remarks>
    /// <example>
    /// <code>
    /// services.AddAuthentication()
    ///     .AddSdJwt("CustomSdJwt", options =>
    ///     {
    ///         options.FallbackKey = myKey;
    ///         options.VerificationOptions = new SdJwtVerificationOptions
    ///         {
    ///             ExpectedIssuer = "https://issuer.example.com",
    ///             ExpectedAudience = "https://api.example.com"
    ///         };
    ///     });
    /// </code>
    /// </example>
    public static AuthenticationBuilder AddSdJwt(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<SdJwtAuthenticationOptions>? configureOptions)
        => builder.AddSdJwt(authenticationScheme, SdJwtAuthenticationDefaults.DisplayName, configureOptions);

    /// <summary>
    /// Adds SD-JWT authentication to the authentication builder with full customization.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="authenticationScheme">The name of the authentication scheme.</param>
    /// <param name="displayName">The display name for the authentication scheme.</param>
    /// <param name="configureOptions">Action to configure the authentication options.</param>
    /// <returns>The authentication builder for method chaining.</returns>
    public static AuthenticationBuilder AddSdJwt(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        string? displayName,
        Action<SdJwtAuthenticationOptions>? configureOptions)
    {
        // Register SD-JWT services if not already registered
        builder.Services.AddSdJwtServices();

        // Register the authentication handler
        return builder.AddScheme<SdJwtAuthenticationOptions, SdJwtAuthenticationHandler>(
            authenticationScheme,
            displayName,
            configureOptions);
    }
}
