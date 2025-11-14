using Microsoft.Extensions.Logging;

namespace HeroSdJwt.Observability;

/// <summary>
/// A logger wrapper that automatically applies log enrichers to all log entries.
/// </summary>
/// <remarks>
/// This class wraps an ILogger instance and automatically enriches log entries
/// with properties from registered <see cref="ILogEnricher"/> instances.
/// </remarks>
internal class EnrichedLogger<T>(ILogger<T> innerLogger) : ILogger<T>
{
    private readonly ILogger<T> innerLogger = innerLogger ?? throw new ArgumentNullException(nameof(innerLogger));

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        return innerLogger.BeginScope(state);
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return innerLogger.IsEnabled(logLevel);
    }

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
            return;

        // Apply enrichers if there are any
        if (LogEnricherCollection.Instance.Count > 0)
        {
            var enrichedState = LogEnricherCollection.Instance.CreateEnrichedState(
                typeof(T).Name,
                logLevel,
                eventId.Id);

            // Merge original state with enriched properties
            if (state is IEnumerable<KeyValuePair<string, object?>> kvps)
            {
                foreach (var kvp in kvps)
                {
                    enrichedState.TryAdd(kvp.Key, kvp.Value);
                }
            }

            using (innerLogger.BeginScope(enrichedState))
            {
                innerLogger.Log(logLevel, eventId, state, exception, formatter);
            }
        }
        else
        {
            innerLogger.Log(logLevel, eventId, state, exception, formatter);
        }
    }
}
