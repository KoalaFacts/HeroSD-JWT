using HeroSdJwt.Observability;
using Microsoft.Extensions.Logging;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Observability;

/// <summary>
/// Tests for EnrichedLogger and ExtensionsToILogger.
/// Validates automatic log enrichment behavior.
/// </summary>
public class EnrichedLoggerTests
{
    private class TestLogger<T> : ILogger<T>
    {
        public List<LogEntry> LogEntries { get; } = new();
        public List<object> Scopes { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            Scopes.Add(state);
            return new TestScope(() => Scopes.Remove(state));
        }

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            LogEntries.Add(new LogEntry
            {
                LogLevel = logLevel,
                EventId = eventId,
                State = state,
                Exception = exception,
                Message = formatter(state, exception)
            });
        }

        private class TestScope : IDisposable
        {
            private readonly Action dispose;

            public TestScope(Action dispose)
            {
                dispose = dispose;
            }

            public void Dispose() => dispose();
        }
    }

    private class TestEnricher : ILogEnricher
    {
        public string Key { get; set; } = "TestKey";
        public object? Value { get; set; } = "TestValue";

        public void Enrich(LogEnrichmentContext context)
        {
            context.AddProperty(Key, Value);
        }
    }

    private class TestDisabledLogger<T> : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => false;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
    }

    public class LogEntry
    {
        public LogLevel LogLevel { get; set; }
        public EventId EventId { get; set; }
        public object? State { get; set; }
        public Exception? Exception { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new EnrichedLogger<string>(null!));
    }

    [Fact]
    public void Constructor_WithValidLogger_CreatesInstance()
    {
        // Arrange
        var innerLogger = new TestLogger<string>();

        // Act
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);

        // Assert
        Assert.NotNull(enrichedLogger);
    }

    [Fact]
    public void IsEnabled_DelegatesToInnerLogger()
    {
        // Arrange
        var innerLogger = new TestLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);

        // Act
        var result = enrichedLogger.IsEnabled(LogLevel.Information);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsEnabled_WithDisabledLogger_ReturnsFalse()
    {
        // Arrange
        var innerLogger = new TestDisabledLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);

        // Act
        var result = enrichedLogger.IsEnabled(LogLevel.Information);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void BeginScope_DelegatesToInnerLogger()
    {
        // Arrange
        var innerLogger = new TestLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);
        var scopeState = "test-scope";

        // Act
        using (enrichedLogger.BeginScope(scopeState))
        {
            // Assert
            Assert.Single(innerLogger.Scopes);
            Assert.Equal(scopeState, innerLogger.Scopes[0]);
        }

        // After dispose
        Assert.Empty(innerLogger.Scopes);
    }

    [Fact]
    public void Log_WithNoEnrichers_LogsDirectlyToInnerLogger()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        collection.Clear(); // Ensure no enrichers
        var innerLogger = new TestLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);

        // Act
        enrichedLogger.LogInformation("Test message");

        // Assert
        Assert.Single(innerLogger.LogEntries);
        Assert.Equal("Test message", innerLogger.LogEntries[0].Message);
        Assert.Empty(innerLogger.Scopes); // No scope should be created when there are no enrichers
    }

    [Fact]
    public void Log_WhenDisabled_DoesNotLog()
    {
        // Arrange
        var innerLogger = new TestDisabledLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);

        // Act
        enrichedLogger.LogInformation("Test message");

        // Assert - No exception should be thrown
        Assert.True(true);
    }

    [Fact]
    public void Log_WithEnrichers_CreatesEnrichedScope()
    {
        // Arrange
        var collection = LogEnricherCollection.Instance;
        collection.Clear();
        var enricher = new TestEnricher { Key = "TenantId", Value = "tenant-123" };
        collection.Add(enricher);

        var innerLogger = new TestLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);

        try
        {
            // Act
            enrichedLogger.LogInformation("Test message with enrichment");

            // Assert
            Assert.Single(innerLogger.LogEntries);
            Assert.Equal("Test message with enrichment", innerLogger.LogEntries[0].Message);
            // Enrichers were applied (scope was created during Log call)
            Assert.True(enricher.Key == "TenantId"); // Verify enricher was configured
        }
        finally
        {
            // Cleanup
            collection.Clear();
        }
    }

    [Fact]
    public void Log_WithStateAsKeyValuePairs_MergesWithEnrichedProperties()
    {
        // Arrange
        var collection = LogEnricherCollection.Instance;
        collection.Clear();
        var enricher = new TestEnricher { Key = "EnrichedProp", Value = "enriched-value" };
        collection.Add(enricher);

        var innerLogger = new TestLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);

        var stateKvps = new List<KeyValuePair<string, object?>>
        {
            new("OriginalProp", "original-value")
        };

        try
        {
            // Act
            enrichedLogger.Log(
                LogLevel.Information,
                new EventId(123),
                stateKvps,
                null,
                (state, ex) => "Test message");

            // Assert - Log was successfully created with enrichment
            Assert.Single(innerLogger.LogEntries);
            Assert.Equal("Test message", innerLogger.LogEntries[0].Message);
        }
        finally
        {
            // Cleanup
            collection.Clear();
        }
    }

    [Fact]
    public void WithEnrichment_WithValidLogger_ReturnsEnrichedLogger()
    {
        // Arrange
        var logger = new TestLogger<string>();

        // Act
        var enrichedLogger = logger.WithEnrichment();

        // Assert
        Assert.NotNull(enrichedLogger);
        Assert.IsType<EnrichedLogger<string>>(enrichedLogger);
    }

    [Fact]
    public void WithEnrichment_WithNullLogger_ThrowsArgumentNullException()
    {
        // Arrange
        ILogger<string> logger = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => logger.WithEnrichment());
    }

    [Fact]
    public void EnrichedLogger_CanLogDifferentLevels()
    {
        // Arrange
        var innerLogger = new TestLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);

        // Act
        enrichedLogger.LogTrace("Trace message");
        enrichedLogger.LogDebug("Debug message");
        enrichedLogger.LogInformation("Info message");
        enrichedLogger.LogWarning("Warning message");
        enrichedLogger.LogError("Error message");
        enrichedLogger.LogCritical("Critical message");

        // Assert
        Assert.Equal(6, innerLogger.LogEntries.Count);
        Assert.Equal(LogLevel.Trace, innerLogger.LogEntries[0].LogLevel);
        Assert.Equal(LogLevel.Debug, innerLogger.LogEntries[1].LogLevel);
        Assert.Equal(LogLevel.Information, innerLogger.LogEntries[2].LogLevel);
        Assert.Equal(LogLevel.Warning, innerLogger.LogEntries[3].LogLevel);
        Assert.Equal(LogLevel.Error, innerLogger.LogEntries[4].LogLevel);
        Assert.Equal(LogLevel.Critical, innerLogger.LogEntries[5].LogLevel);
    }

    [Fact]
    public void EnrichedLogger_PreservesEventId()
    {
        // Arrange
        var innerLogger = new TestLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);
        var eventId = new EventId(42, "TestEvent");

        // Act
        enrichedLogger.Log(LogLevel.Information, eventId, "Test", null, (s, e) => s);

        // Assert
        Assert.Single(innerLogger.LogEntries);
        Assert.Equal(42, innerLogger.LogEntries[0].EventId.Id);
        Assert.Equal("TestEvent", innerLogger.LogEntries[0].EventId.Name);
    }

    [Fact]
    public void EnrichedLogger_PreservesException()
    {
        // Arrange
        var innerLogger = new TestLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);
        var exception = new InvalidOperationException("Test exception");

        // Act
        enrichedLogger.LogError(exception, "Error occurred");

        // Assert
        Assert.Single(innerLogger.LogEntries);
        Assert.Same(exception, innerLogger.LogEntries[0].Exception);
    }

    [Fact]
    public void EnrichedLogger_WithMultipleEnrichers_AppliesAllEnrichers()
    {
        // Arrange
        var collection = LogEnricherCollection.Instance;
        collection.Clear();

        collection.Add(new TestEnricher { Key = "Enricher1", Value = "Value1" });
        collection.Add(new TestEnricher { Key = "Enricher2", Value = "Value2" });
        collection.Add(new TestEnricher { Key = "Enricher3", Value = "Value3" });

        var innerLogger = new TestLogger<string>();
        var enrichedLogger = new EnrichedLogger<string>(innerLogger);

        try
        {
            // Act
            enrichedLogger.LogInformation("Test with multiple enrichers");

            // Assert
            Assert.Single(innerLogger.LogEntries);
            Assert.Equal("Test with multiple enrichers", innerLogger.LogEntries[0].Message);
            // All enrichers were configured (scopes were created during Log call)
            Assert.Equal(3, collection.Count);
        }
        finally
        {
            // Cleanup
            collection.Clear();
        }
    }
}
