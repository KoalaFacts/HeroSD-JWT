using Microsoft.Extensions.Logging;

namespace HeroSdJwt.Observability;

/// <summary>
/// A logger wrapper that automatically applies log enrichers to all log entries.
/// </summary>
/// <remarks>
/// This class wraps an ILogger instance and automatically enriches log entries
/// with properties from registered <see cref="ILogEnricher"/> instances.
/// </remarks>
internal class EnrichedLogger<T> : ILogger<T>
{
    private readonly ILogger<T> _innerLogger;

    public EnrichedLogger(ILogger<T> innerLogger)
    {
        _innerLogger = innerLogger ?? throw new ArgumentNullException(nameof(innerLogger));
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        return _innerLogger.BeginScope(state);
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return _innerLogger.IsEnabled(logLevel);
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

            using (_innerLogger.BeginScope(enrichedState))
            {
                _innerLogger.Log(logLevel, eventId, state, exception, formatter);
            }
        }
        else
        {
            _innerLogger.Log(logLevel, eventId, state, exception, formatter);
        }
    }
}
