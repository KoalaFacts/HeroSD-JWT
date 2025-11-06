using HeroSdJwt.Observability;
using Microsoft.Extensions.Logging;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Observability;

/// <summary>
/// Tests for LogEnrichmentContext.
/// Validates property management and enrichment context behavior.
/// </summary>
public class LogEnrichmentContextTests
{
    [Fact]
    public void AddProperty_WithValidKeyAndValue_AddsProperty()
    {
        // Arrange
        var context = new LogEnrichmentContext();
        var key = "TenantId";
        var value = "tenant-123";

        // Act
        context.AddProperty(key, value);

        // Assert
        Assert.True(context.HasProperty(key));
        Assert.Equal(value, context.Properties[key]);
    }

    [Fact]
    public void AddProperty_WithNullValue_AddsPropertyWithNullValue()
    {
        // Arrange
        var context = new LogEnrichmentContext();
        var key = "OptionalValue";

        // Act
        context.AddProperty(key, null);

        // Assert
        Assert.True(context.HasProperty(key));
        Assert.Null(context.Properties[key]);
    }

    [Fact]
    public void AddProperty_WithDuplicateKey_OverwritesExistingValue()
    {
        // Arrange
        var context = new LogEnrichmentContext();
        var key = "Counter";

        // Act
        context.AddProperty(key, 1);
        context.AddProperty(key, 2);

        // Assert
        Assert.True(context.HasProperty(key));
        Assert.Equal(2, context.Properties[key]);
    }

    [Fact]
    public void RemoveProperty_WithExistingKey_RemovesPropertyAndReturnsTrue()
    {
        // Arrange
        var context = new LogEnrichmentContext();
        var key = "UserId";
        context.AddProperty(key, "user-456");

        // Act
        var result = context.RemoveProperty(key);

        // Assert
        Assert.True(result);
        Assert.False(context.HasProperty(key));
    }

    [Fact]
    public void RemoveProperty_WithNonExistentKey_ReturnsFalse()
    {
        // Arrange
        var context = new LogEnrichmentContext();

        // Act
        var result = context.RemoveProperty("NonExistent");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void HasProperty_WithExistingKey_ReturnsTrue()
    {
        // Arrange
        var context = new LogEnrichmentContext();
        var key = "CorrelationId";
        context.AddProperty(key, "corr-789");

        // Act
        var result = context.HasProperty(key);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void HasProperty_WithNonExistentKey_ReturnsFalse()
    {
        // Arrange
        var context = new LogEnrichmentContext();

        // Act
        var result = context.HasProperty("DoesNotExist");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Properties_ReturnsReadOnlyDictionary()
    {
        // Arrange
        var context = new LogEnrichmentContext();
        context.AddProperty("Key1", "Value1");
        context.AddProperty("Key2", "Value2");

        // Act
        var properties = context.Properties;

        // Assert
        Assert.IsAssignableFrom<IReadOnlyDictionary<string, object?>>(properties);
        Assert.Equal(2, properties.Count);
        Assert.Equal("Value1", properties["Key1"]);
        Assert.Equal("Value2", properties["Key2"]);
    }

    [Fact]
    public void OperationType_CanBeSetAndRetrieved()
    {
        // Arrange
        var context = new LogEnrichmentContext
        {
            // Act
            OperationType = "Verification"
        };

        // Assert
        Assert.Equal("Verification", context.OperationType);
    }

    [Fact]
    public void LogLevel_CanBeSetAndRetrieved()
    {
        // Arrange
        var context = new LogEnrichmentContext
        {
            // Act
            LogLevel = LogLevel.Warning
        };

        // Assert
        Assert.Equal(LogLevel.Warning, context.LogLevel);
    }

    [Fact]
    public void EventId_CanBeSetAndRetrieved()
    {
        // Arrange
        var context = new LogEnrichmentContext
        {
            // Act
            EventId = 12345
        };

        // Assert
        Assert.Equal(12345, context.EventId);
    }

    [Fact]
    public void DefaultOperationType_IsEmptyString()
    {
        // Arrange & Act
        var context = new LogEnrichmentContext();

        // Assert
        Assert.Equal(string.Empty, context.OperationType);
    }

    [Fact]
    public void DefaultLogLevel_IsNone()
    {
        // Arrange & Act
        var context = new LogEnrichmentContext();

        // Assert
        Assert.Equal(default(LogLevel), context.LogLevel);
    }

    [Fact]
    public void DefaultEventId_IsZero()
    {
        // Arrange & Act
        var context = new LogEnrichmentContext();

        // Assert
        Assert.Equal(0, context.EventId);
    }

    [Fact]
    public void MultipleProperties_CanBeAddedAndRetrieved()
    {
        // Arrange
        var context = new LogEnrichmentContext();

        // Act
        context.AddProperty("Prop1", "Value1");
        context.AddProperty("Prop2", 42);
        context.AddProperty("Prop3", true);
        context.AddProperty("Prop4", DateTime.UtcNow);

        // Assert
        Assert.Equal(4, context.Properties.Count);
        Assert.Equal("Value1", context.Properties["Prop1"]);
        Assert.Equal(42, context.Properties["Prop2"]);
        Assert.Equal(true, context.Properties["Prop3"]);
        Assert.IsType<DateTime>(context.Properties["Prop4"]);
    }
}
