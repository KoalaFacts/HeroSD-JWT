using Microsoft.Extensions.Logging;

namespace HeroSdJwt.Observability;

/// <summary>
/// Plugin interface for enriching log entries with custom metadata.
/// </summary>
/// <remarks>
/// Implement this interface to add contextual information to all HeroSD-JWT logs,
/// such as tenant IDs, correlation IDs, or other application-specific metadata.
/// <para>
/// Example implementation:
/// <code>
/// public class TenantLogEnricher : ILogEnricher
/// {
///     private readonly ITenantContext tenantContext;
///
///     public TenantLogEnricher(ITenantContext tenantContext)
///     {
///         tenantContext = tenantContext;
///     }
///
///     public void Enrich(LogEnrichmentContext context)
///     {
///         context.AddProperty("TenantId", tenantContext.CurrentTenantId);
///         context.AddProperty("UserId", tenantContext.CurrentUserId);
///     }
/// }
/// </code>
/// </para>
/// </remarks>
public interface ILogEnricher
{
    /// <summary>
    /// Enriches the log entry with additional properties.
    /// </summary>
    /// <param name="context">The enrichment context containing the log entry.</param>
    void Enrich(LogEnrichmentContext context);
}

/// <summary>
/// Context provided to log enrichers containing the log entry and supporting metadata.
/// </summary>
public class LogEnrichmentContext
{
    private readonly Dictionary<string, object?> properties = new();

    /// <summary>
    /// Gets the operation type being logged (e.g., "Issuance", "Verification", "Presentation").
    /// </summary>
    public string OperationType { get; internal set; } = string.Empty;

    /// <summary>
    /// Gets the log level of the entry.
    /// </summary>
    public LogLevel LogLevel { get; internal set; }

    /// <summary>
    /// Gets the event ID of the log entry.
    /// </summary>
    public int EventId { get; internal set; }

    /// <summary>
    /// Gets all enriched properties.
    /// </summary>
    public IReadOnlyDictionary<string, object?> Properties => properties;

    /// <summary>
    /// Adds a property to the log entry.
    /// </summary>
    /// <param name="key">The property key.</param>
    /// <param name="value">The property value.</param>
    public void AddProperty(string key, object? value)
    {
        properties[key] = value;
    }

    /// <summary>
    /// Removes a property from the log entry.
    /// </summary>
    /// <param name="key">The property key to remove.</param>
    /// <returns>true if the property was removed; otherwise, false.</returns>
    public bool RemoveProperty(string key)
    {
        return properties.Remove(key);
    }

    /// <summary>
    /// Checks if a property exists in the log entry.
    /// </summary>
    /// <param name="key">The property key.</param>
    /// <returns>true if the property exists; otherwise, false.</returns>
    public bool HasProperty(string key)
    {
        return properties.ContainsKey(key);
    }
}
