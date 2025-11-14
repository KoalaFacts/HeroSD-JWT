using HeroSdJwt.Observability;
using Microsoft.Extensions.Logging;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Observability;

/// <summary>
/// Tests for LogEnricherCollection.
/// Validates enricher management and log enrichment behavior.
/// </summary>
public class LogEnricherCollectionTests
{
    private class TestEnricher : ILogEnricher
    {
        public string PropertyKey { get; set; } = "TestKey";
        public object? PropertyValue { get; set; } = "TestValue";
        public bool EnrichCalled { get; private set; }

        public void Enrich(LogEnrichmentContext context)
        {
            EnrichCalled = true;
            context.AddProperty(PropertyKey, PropertyValue);
        }
    }

    private class ThrowingEnricher : ILogEnricher
    {
        public void Enrich(LogEnrichmentContext context)
        {
            throw new InvalidOperationException("Enricher failed");
        }
    }

    [Fact]
    public void Instance_IsSingleton()
    {
        // Arrange & Act
        var instance1 = LogEnricherCollection.Instance;
        var instance2 = LogEnricherCollection.Instance;

        // Assert
        Assert.Same(instance1, instance2);
    }

    [Fact]
    public void Add_WithValidEnricher_AddsToCollection()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        var enricher = new TestEnricher();

        // Act
        collection.Add(enricher);

        // Assert
        Assert.Equal(1, collection.Count);
    }

    [Fact]
    public void Add_WithNullEnricher_ThrowsArgumentNullException()
    {
        // Arrange
        var collection = new LogEnricherCollection();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => collection.Add(null!));
    }

    [Fact]
    public void Add_MultipleEnrichers_IncreasesCount()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        var enricher1 = new TestEnricher { PropertyKey = "Key1" };
        var enricher2 = new TestEnricher { PropertyKey = "Key2" };

        // Act
        collection.Add(enricher1);
        collection.Add(enricher2);

        // Assert
        Assert.Equal(2, collection.Count);
    }

    [Fact]
    public void Remove_WithExistingEnricher_RemovesAndReturnsTrue()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        var enricher = new TestEnricher();
        collection.Add(enricher);

        // Act
        var result = collection.Remove(enricher);

        // Assert
        Assert.True(result);
        Assert.Equal(0, collection.Count);
    }

    [Fact]
    public void Remove_WithNonExistentEnricher_ReturnsFalse()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        var enricher = new TestEnricher();

        // Act
        var result = collection.Remove(enricher);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Remove_WithNullEnricher_ReturnsFalse()
    {
        // Arrange
        var collection = new LogEnricherCollection();

        // Act
        var result = collection.Remove(null!);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Clear_RemovesAllEnrichers()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        collection.Add(new TestEnricher());
        collection.Add(new TestEnricher());
        collection.Add(new TestEnricher());

        // Act
        collection.Clear();

        // Assert
        Assert.Equal(0, collection.Count);
    }

    [Fact]
    public void Clear_OnEmptyCollection_DoesNotThrow()
    {
        // Arrange
        var collection = new LogEnricherCollection();

        // Act
        collection.Clear();

        // Assert
        Assert.Equal(0, collection.Count);
    }

    [Fact]
    public void Count_ReturnsCorrectNumber()
    {
        // Arrange
        var collection = new LogEnricherCollection();

        // Act & Assert
        Assert.Equal(0, collection.Count);

        collection.Add(new TestEnricher());
        Assert.Equal(1, collection.Count);

        collection.Add(new TestEnricher());
        Assert.Equal(2, collection.Count);

        collection.Clear();
        Assert.Equal(0, collection.Count);
    }

    [Fact]
    public void CreateEnrichedState_WithNoEnrichers_ReturnsEmptyDictionary()
    {
        // Arrange
        var collection = new LogEnricherCollection();

        // Act
        var state = collection.CreateEnrichedState("TestOp", LogLevel.Information, 123);

        // Assert
        Assert.NotNull(state);
        Assert.Empty(state);
    }

    [Fact]
    public void CreateEnrichedState_WithSingleEnricher_AddsEnricherProperties()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        var enricher = new TestEnricher
        {
            PropertyKey = "TenantId",
            PropertyValue = "tenant-123"
        };
        collection.Add(enricher);

        // Act
        var state = collection.CreateEnrichedState("Verification", LogLevel.Information, 456);

        // Assert
        Assert.NotEmpty(state);
        Assert.True(state.ContainsKey("TenantId"));
        Assert.Equal("tenant-123", state["TenantId"]);
        Assert.True(enricher.EnrichCalled);
    }

    [Fact]
    public void CreateEnrichedState_WithMultipleEnrichers_AddsAllProperties()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        var enricher1 = new TestEnricher
        {
            PropertyKey = "TenantId",
            PropertyValue = "tenant-123"
        };
        var enricher2 = new TestEnricher
        {
            PropertyKey = "UserId",
            PropertyValue = "user-456"
        };
        collection.Add(enricher1);
        collection.Add(enricher2);

        // Act
        var state = collection.CreateEnrichedState("Issuance", LogLevel.Debug, 789);

        // Assert
        Assert.Equal(2, state.Count);
        Assert.Equal("tenant-123", state["TenantId"]);
        Assert.Equal("user-456", state["UserId"]);
    }

    [Fact]
    public void CreateEnrichedState_PassesCorrectContextProperties()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        LogEnrichmentContext? capturedContext = null;
        var enricher = new TestEnricher();

        // Create a custom enricher that captures the context
        collection.Add(new CustomEnricher(ctx => capturedContext = ctx));

        // Act
        collection.CreateEnrichedState("Presentation", LogLevel.Warning, 999);

        // Assert
        Assert.NotNull(capturedContext);
        Assert.Equal("Presentation", capturedContext.OperationType);
        Assert.Equal(LogLevel.Warning, capturedContext.LogLevel);
        Assert.Equal(999, capturedContext.EventId);
    }

    [Fact]
    public void EnrichLog_WithThrowingEnricher_SilentlyIgnoresException()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        var throwingEnricher = new ThrowingEnricher();
        var workingEnricher = new TestEnricher
        {
            PropertyKey = "ValidKey",
            PropertyValue = "ValidValue"
        };

        collection.Add(throwingEnricher);
        collection.Add(workingEnricher);

        var context = new LogEnrichmentContext
        {
            OperationType = "Test",
            LogLevel = LogLevel.Information,
            EventId = 1
        };

        // Act - Should not throw
        collection.EnrichLog(context);

        // Assert - The working enricher should still have been called
        Assert.True(workingEnricher.EnrichCalled);
        Assert.True(context.HasProperty("ValidKey"));
    }

    [Fact]
#pragma warning disable xUnit1051 // Test-specific async operations
    public async Task ThreadSafety_MultipleThreadsAddingEnrichers_AllAreAdded()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        var tasks = new List<Task>();
        const int threadCount = 10;

        // Act
        for (int i = 0; i < threadCount; i++)
        {
            tasks.Add(Task.Run(() => collection.Add(new TestEnricher())));
        }

        await Task.WhenAll(tasks);

        // Assert
        Assert.Equal(threadCount, collection.Count);
    }
#pragma warning restore xUnit1051

    [Fact]
#pragma warning disable xUnit1051 // Test-specific async operations
    public async Task ThreadSafety_AddingAndRemovingConcurrently_DoesNotThrow()
    {
        // Arrange
        var collection = new LogEnricherCollection();
        var enrichers = Enumerable.Range(0, 10).Select(_ => new TestEnricher()).ToList();
        var tasks = new List<Task>();

        // Add initial enrichers
        foreach (var enricher in enrichers)
        {
            collection.Add(enricher);
        }

        // Act - Mix of add, remove, and count operations
        for (int i = 0; i < 20; i++)
        {
            var index = i % enrichers.Count;
            tasks.Add(Task.Run(() =>
            {
                collection.Remove(enrichers[index]);
                _ = collection.Count;
                collection.Add(enrichers[index]);
            }));
        }

        // Assert - Should not throw
        await Task.WhenAll(tasks);
        Assert.True(collection.Count >= 0);
    }
#pragma warning restore xUnit1051

    private class CustomEnricher(Action<LogEnrichmentContext> action) : ILogEnricher
    {
        private readonly Action<LogEnrichmentContext> action = action;

        public void Enrich(LogEnrichmentContext context)
        {
            action(context);
        }
    }
}
