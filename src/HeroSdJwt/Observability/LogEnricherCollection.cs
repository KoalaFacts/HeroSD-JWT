using Microsoft.Extensions.Logging;

namespace HeroSdJwt.Observability;

/// <summary>
/// A collection of log enrichers that can be applied to log entries.
/// </summary>
/// <remarks>
/// This class manages a thread-safe collection of <see cref="ILogEnricher"/> instances
/// and provides methods to apply all enrichers to a log context.
/// </remarks>
public class LogEnricherCollection
{
    private readonly List<ILogEnricher> _enrichers = new();
    private readonly object _lock = new();

    /// <summary>
    /// Gets the singleton instance of the log enricher collection.
    /// </summary>
    public static LogEnricherCollection Instance { get; } = new();

    /// <summary>
    /// Adds a log enricher to the collection.
    /// </summary>
    /// <param name="enricher">The enricher to add.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="enricher"/> is null.</exception>
    public void Add(ILogEnricher enricher)
    {
        if (enricher == null)
            throw new ArgumentNullException(nameof(enricher));

        lock (_lock)
        {
            _enrichers.Add(enricher);
        }
    }

    /// <summary>
    /// Removes a log enricher from the collection.
    /// </summary>
    /// <param name="enricher">The enricher to remove.</param>
    /// <returns>true if the enricher was removed; otherwise, false.</returns>
    public bool Remove(ILogEnricher enricher)
    {
        if (enricher == null)
            return false;

        lock (_lock)
        {
            return _enrichers.Remove(enricher);
        }
    }

    /// <summary>
    /// Clears all enrichers from the collection.
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _enrichers.Clear();
        }
    }

    /// <summary>
    /// Gets the number of enrichers in the collection.
    /// </summary>
    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _enrichers.Count;
            }
        }
    }

    /// <summary>
    /// Applies all enrichers to the provided log context.
    /// </summary>
    /// <param name="context">The context to enrich.</param>
    internal void EnrichLog(LogEnrichmentContext context)
    {
        List<ILogEnricher> enrichersCopy;
        lock (_lock)
        {
            enrichersCopy = new List<ILogEnricher>(_enrichers);
        }

        foreach (var enricher in enrichersCopy)
        {
            try
            {
                enricher.Enrich(context);
            }
            catch
            {
                // Silently ignore enricher failures to prevent logging infrastructure
                // from breaking the application
            }
        }
    }

    /// <summary>
    /// Creates a scoped log state with enriched properties for use with ILogger.BeginScope.
    /// </summary>
    /// <param name="operationType">The operation type being logged.</param>
    /// <param name="logLevel">The log level.</param>
    /// <param name="eventId">The event ID.</param>
    /// <returns>A dictionary containing all enriched properties.</returns>
    internal Dictionary<string, object?> CreateEnrichedState(string operationType, LogLevel logLevel, int eventId)
    {
        var context = new LogEnrichmentContext
        {
            OperationType = operationType,
            LogLevel = logLevel,
            EventId = eventId
        };

        EnrichLog(context);

        return new Dictionary<string, object?>(context.Properties);
    }
}
