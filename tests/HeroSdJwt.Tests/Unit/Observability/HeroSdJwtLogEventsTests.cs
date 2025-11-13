using HeroSdJwt.Observability;
using Microsoft.Extensions.Logging;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Observability;

/// <summary>
/// Tests for HeroSdJwtLogEvents source-generated logging methods.
/// Validates event IDs, log levels, and message formatting.
/// </summary>
public class HeroSdJwtLogEventsTests
{
    private readonly TestLogger logger;

    public HeroSdJwtLogEventsTests()
    {
        logger = new TestLogger();
    }

    #region Issuance Tests (1000-1999)

    [Fact]
    public void LogIssuanceStarted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogIssuanceStarted(5, 3, 2);

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(1000, entry.EventId.Id);
        Assert.Equal(LogLevel.Information, entry.LogLevel);
        Assert.Contains("5 claims", entry.Message);
        Assert.Contains("3 selective claims", entry.Message);
        Assert.Contains("2 decoys", entry.Message);
    }

    [Fact]
    public void LogIssuanceCompleted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogIssuanceCompleted(10, "ES256");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(1001, entry.EventId.Id);
        Assert.Equal(LogLevel.Information, entry.LogLevel);
        Assert.Contains("10 disclosures", entry.Message);
        Assert.Contains("ES256", entry.Message);
    }

    [Fact]
    public void LogDisclosureGenerated_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogDisclosureGenerated("user.email");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(1002, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("user.email", entry.Message);
    }

    [Fact]
    public void LogDecoysGenerated_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogDecoysGenerated(5);

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(1003, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("5 decoy digests", entry.Message);
    }

    [Fact]
    public void LogIssuanceFailed_LogsWithCorrectEventIdAndLevel()
    {
        // Arrange
        var exception = new InvalidOperationException("Test error");

        // Act
        logger.LogIssuanceFailed(exception, "Issuance failed");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(1004, entry.EventId.Id);
        Assert.Equal(LogLevel.Error, entry.LogLevel);
        Assert.Contains("Issuance failed", entry.Message);
        Assert.Equal(exception, entry.Exception);
    }

    #endregion

    #region Verification Tests (2000-2999)

    [Fact]
    public void LogVerificationStarted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogVerificationStarted();

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2000, entry.EventId.Id);
        Assert.Equal(LogLevel.Information, entry.LogLevel);
        Assert.Contains("verification started", entry.Message);
    }

    [Fact]
    public void LogVerificationCompleted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogVerificationCompleted(8);

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2001, entry.EventId.Id);
        Assert.Equal(LogLevel.Information, entry.LogLevel);
        Assert.Contains("8 disclosures", entry.Message);
    }

    [Fact]
    public void LogVerificationFailed_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogVerificationFailed("INVALID_SIGNATURE");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2002, entry.EventId.Id);
        Assert.Equal(LogLevel.Warning, entry.LogLevel);
        Assert.Contains("INVALID_SIGNATURE", entry.Message);
    }

    [Fact]
    public void LogSignatureValidationStarted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogSignatureValidationStarted("ES256");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2010, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("ES256", entry.Message);
    }

    [Fact]
    public void LogSignatureValidationSucceeded_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogSignatureValidationSucceeded();

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2011, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("successful", entry.Message);
    }

    [Fact]
    public void LogSignatureValidationFailed_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogSignatureValidationFailed("Invalid signature bytes");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2012, entry.EventId.Id);
        Assert.Equal(LogLevel.Warning, entry.LogLevel);
        Assert.Contains("Invalid signature bytes", entry.Message);
    }

    [Fact]
    public void LogDigestValidationStarted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogDigestValidationStarted(12);

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2020, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("12 disclosures", entry.Message);
    }

    [Fact]
    public void LogDigestValidationSucceeded_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogDigestValidationSucceeded(12);

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2021, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("12 disclosures", entry.Message);
    }

    [Fact]
    public void LogDigestValidationFailed_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogDigestValidationFailed("Digest mismatch");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2022, entry.EventId.Id);
        Assert.Equal(LogLevel.Warning, entry.LogLevel);
        Assert.Contains("Digest mismatch", entry.Message);
    }

    [Fact]
    public void LogKeyResolutionStarted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogKeyResolutionStarted("key-123");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2030, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("key-123", entry.Message);
    }

    [Fact]
    public void LogKeyResolutionStarted_WithNullKeyId_LogsCorrectly()
    {
        // Act
        logger.LogKeyResolutionStarted(null);

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2030, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
    }

    [Fact]
    public void LogKeyResolutionSucceeded_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogKeyResolutionSucceeded();

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2031, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("successful", entry.Message);
    }

    [Fact]
    public void LogKeyResolutionFailed_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogKeyResolutionFailed("key-456");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2032, entry.EventId.Id);
        Assert.Equal(LogLevel.Error, entry.LogLevel);
        Assert.Contains("key-456", entry.Message);
    }

    [Fact]
    public void LogKeyResolutionFailed_WithNullKeyId_LogsCorrectly()
    {
        // Act
        logger.LogKeyResolutionFailed(null);

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(2032, entry.EventId.Id);
        Assert.Equal(LogLevel.Error, entry.LogLevel);
    }

    #endregion

    #region Presentation Tests (3000-3999)

    [Fact]
    public void LogPresentationStarted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogPresentationStarted(7);

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(3000, entry.EventId.Id);
        Assert.Equal(LogLevel.Information, entry.LogLevel);
        Assert.Contains("7 requested claims", entry.Message);
    }

    [Fact]
    public void LogPresentationCompleted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogPresentationCompleted(5);

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(3001, entry.EventId.Id);
        Assert.Equal(LogLevel.Information, entry.LogLevel);
        Assert.Contains("5 disclosures", entry.Message);
    }

    [Fact]
    public void LogClaimIncluded_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogClaimIncluded("user.address.street");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(3002, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("user.address.street", entry.Message);
        Assert.Contains("included", entry.Message);
    }

    [Fact]
    public void LogClaimExcluded_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogClaimExcluded("user.ssn");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(3003, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("user.ssn", entry.Message);
        Assert.Contains("excluded", entry.Message);
    }

    [Fact]
    public void LogPresentationFailed_LogsWithCorrectEventIdAndLevel()
    {
        // Arrange
        var exception = new ArgumentException("Invalid claim path");

        // Act
        logger.LogPresentationFailed(exception, "Presentation failed");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(3004, entry.EventId.Id);
        Assert.Equal(LogLevel.Error, entry.LogLevel);
        Assert.Contains("Presentation failed", entry.Message);
        Assert.Equal(exception, entry.Exception);
    }

    #endregion

    #region Key Binding Tests (4000-4999)

    [Fact]
    public void LogKeyBindingGenerationStarted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogKeyBindingGenerationStarted();

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(4000, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("generation started", entry.Message);
    }

    [Fact]
    public void LogKeyBindingGenerated_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogKeyBindingGenerated("ES256");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(4001, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("ES256", entry.Message);
        Assert.Contains("successfully", entry.Message);
    }

    [Fact]
    public void LogKeyBindingValidationStarted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogKeyBindingValidationStarted();

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(4010, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("validation started", entry.Message);
    }

    [Fact]
    public void LogKeyBindingValidationSucceeded_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogKeyBindingValidationSucceeded();

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(4011, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("successful", entry.Message);
    }

    [Fact]
    public void LogKeyBindingValidationFailed_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogKeyBindingValidationFailed("Invalid sd_hash");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(4012, entry.EventId.Id);
        Assert.Equal(LogLevel.Warning, entry.LogLevel);
        Assert.Contains("Invalid sd_hash", entry.Message);
    }

    #endregion

    #region Cryptography Tests (5000-5999)

    [Fact]
    public void LogSigningStarted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogSigningStarted("ES256");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(5000, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("ES256", entry.Message);
    }

    [Fact]
    public void LogSigningCompleted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogSigningCompleted();

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(5001, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("completed", entry.Message);
    }

    [Fact]
    public void LogSigningFailed_LogsWithCorrectEventIdAndLevel()
    {
        // Arrange
        var exception = new InvalidOperationException("Key not found");

        // Act
        logger.LogSigningFailed(exception, "Signing failed");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(5002, entry.EventId.Id);
        Assert.Equal(LogLevel.Error, entry.LogLevel);
        Assert.Contains("Signing failed", entry.Message);
        Assert.Equal(exception, entry.Exception);
    }

    [Fact]
    public void LogHashCalculationStarted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogHashCalculationStarted("SHA-256");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(5010, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("SHA-256", entry.Message);
    }

    [Fact]
    public void LogHashCalculationCompleted_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogHashCalculationCompleted();

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(5011, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("completed", entry.Message);
    }

    #endregion

    #region General Tests (6000-6999)

    [Fact]
    public void LogSecurityWarning_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogSecurityWarning("Weak algorithm detected");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(6000, entry.EventId.Id);
        Assert.Equal(LogLevel.Warning, entry.LogLevel);
        Assert.Contains("Weak algorithm detected", entry.Message);
    }

    [Fact]
    public void LogUnexpectedError_LogsWithCorrectEventIdAndLevel()
    {
        // Arrange
        var exception = new Exception("Unexpected condition");

        // Act
        logger.LogUnexpectedError(exception, "Something went wrong");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(6001, entry.EventId.Id);
        Assert.Equal(LogLevel.Error, entry.LogLevel);
        Assert.Contains("Something went wrong", entry.Message);
        Assert.Equal(exception, entry.Exception);
    }

    [Fact]
    public void LogConfiguration_LogsWithCorrectEventIdAndLevel()
    {
        // Act
        logger.LogConfiguration("TimeProvider=System, ClockSkew=5m");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Equal(6002, entry.EventId.Id);
        Assert.Equal(LogLevel.Debug, entry.LogLevel);
        Assert.Contains("TimeProvider=System", entry.Message);
    }

    #endregion

    #region Edge Case Tests

    [Fact]
    public void MultipleLogCalls_AllCaptured()
    {
        // Act
        logger.LogIssuanceStarted(1, 1, 0);
        logger.LogVerificationStarted();
        logger.LogPresentationStarted(3);

        // Assert
        Assert.Equal(3, logger.LogEntries.Count);
        Assert.Equal(1000, logger.LogEntries[0].EventId.Id);
        Assert.Equal(2000, logger.LogEntries[1].EventId.Id);
        Assert.Equal(3000, logger.LogEntries[2].EventId.Id);
    }

    [Fact]
    public void LogWithZeroValues_WorksCorrectly()
    {
        // Act
        logger.LogIssuanceStarted(0, 0, 0);
        logger.LogVerificationCompleted(0);

        // Assert
        Assert.Equal(2, logger.LogEntries.Count);
        Assert.Contains("0 claims", logger.LogEntries[0].Message);
        Assert.Contains("0 disclosures", logger.LogEntries[1].Message);
    }

    [Fact]
    public void LogWithLargeNumbers_WorksCorrectly()
    {
        // Act
        logger.LogIssuanceCompleted(999999, "ES256");

        // Assert
        var entry = Assert.Single(logger.LogEntries);
        Assert.Contains("999999", entry.Message);
    }

    [Fact]
    public void LogWithSpecialCharacters_WorksCorrectly()
    {
        // Act
        logger.LogClaimIncluded("user.data[0].value");
        logger.LogSecurityWarning("Algorithm 'none' is not allowed");

        // Assert
        Assert.Equal(2, logger.LogEntries.Count);
        Assert.Contains("user.data[0].value", logger.LogEntries[0].Message);
        Assert.Contains("'none'", logger.LogEntries[1].Message);
    }

    [Fact]
    public void LogWithEmptyStrings_WorksCorrectly()
    {
        // Act
        logger.LogDisclosureGenerated("");
        logger.LogConfiguration("");

        // Assert
        Assert.Equal(2, logger.LogEntries.Count);
    }

    #endregion

    #region Test Helper Class

    private class TestLogger : ILogger
    {
        public List<LogEntry> LogEntries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            return null;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

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
                Message = formatter(state, exception),
                Exception = exception
            });
        }
    }

    private class LogEntry
    {
        public LogLevel LogLevel { get; init; }
        public EventId EventId { get; init; }
        public string Message { get; init; } = string.Empty;
        public Exception? Exception { get; init; }
    }

    #endregion
}
