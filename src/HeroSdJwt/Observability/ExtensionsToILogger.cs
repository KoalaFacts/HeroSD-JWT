#pragma warning disable IDE0130 // Namespace does not match folder structure - intentional for ILogger extensions
namespace Microsoft.Extensions.Logging;
#pragma warning restore IDE0130

/// <summary>
/// Extension methods for working with enriched loggers in HeroSD-JWT.
/// </summary>
public static class ExtensionsToILogger
{
    /// <summary>
    /// Wraps an ILogger with automatic log enrichment support.
    /// </summary>
    /// <typeparam name="T">The type being logged.</typeparam>
    /// <param name="logger">The logger to wrap.</param>
    /// <returns>An enriched logger that applies all registered enrichers.</returns>
    public static ILogger<T> WithEnrichment<T>(this ILogger<T> logger)
    {
        if (logger == null)
            throw new ArgumentNullException(nameof(logger));

        return new HeroSdJwt.Observability.EnrichedLogger<T>(logger);
    }
}
