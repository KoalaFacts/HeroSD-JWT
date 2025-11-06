using Microsoft.Extensions.Logging;

namespace HeroSdJwt.Observability;

/// <summary>
/// Centralized log event IDs and source-generated logging messages for HeroSD-JWT.
/// </summary>
/// <remarks>
/// This class uses source-generated logging (LoggerMessageAttribute) for high-performance,
/// zero-allocation logging. Event IDs are organized by component and operation.
/// </remarks>
internal static partial class HeroSdJwtLogEvents
{
    // Event ID ranges:
    // 1000-1999: Issuance operations
    // 2000-2999: Verification operations
    // 3000-3999: Presentation operations
    // 4000-4999: Key binding operations
    // 5000-5999: Cryptography operations
    // 6000-6999: General errors and warnings

    #region Issuance (1000-1999)

    [LoggerMessage(
        EventId = 1000,
        Level = LogLevel.Information,
        Message = "SD-JWT issuance started with {ClaimCount} claims, {SelectiveClaimCount} selective claims, {DecoyCount} decoys")]
    public static partial void LogIssuanceStarted(
        this ILogger logger,
        int claimCount,
        int selectiveClaimCount,
        int decoyCount);

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Information,
        Message = "SD-JWT issued successfully with {DisclosureCount} disclosures using algorithm {Algorithm}")]
    public static partial void LogIssuanceCompleted(
        this ILogger logger,
        int disclosureCount,
        string algorithm);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Debug,
        Message = "Generated disclosure for claim path: {ClaimPath}")]
    public static partial void LogDisclosureGenerated(
        this ILogger logger,
        string claimPath);

    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Debug,
        Message = "Generated {DecoyCount} decoy digests for privacy enhancement")]
    public static partial void LogDecoysGenerated(
        this ILogger logger,
        int decoyCount);

    [LoggerMessage(
        EventId = 1004,
        Level = LogLevel.Error,
        Message = "SD-JWT issuance failed: {ErrorMessage}")]
    public static partial void LogIssuanceFailed(
        this ILogger logger,
        Exception exception,
        string errorMessage);

    #endregion

    #region Verification (2000-2999)

    [LoggerMessage(
        EventId = 2000,
        Level = LogLevel.Information,
        Message = "SD-JWT verification started")]
    public static partial void LogVerificationStarted(
        this ILogger logger);

    [LoggerMessage(
        EventId = 2001,
        Level = LogLevel.Information,
        Message = "SD-JWT verification completed successfully with {DisclosureCount} disclosures")]
    public static partial void LogVerificationCompleted(
        this ILogger logger,
        int disclosureCount);

    [LoggerMessage(
        EventId = 2002,
        Level = LogLevel.Warning,
        Message = "SD-JWT verification failed with error code: {ErrorCode}")]
    public static partial void LogVerificationFailed(
        this ILogger logger,
        string errorCode);

    [LoggerMessage(
        EventId = 2010,
        Level = LogLevel.Debug,
        Message = "Signature validation started using algorithm {Algorithm}")]
    public static partial void LogSignatureValidationStarted(
        this ILogger logger,
        string algorithm);

    [LoggerMessage(
        EventId = 2011,
        Level = LogLevel.Debug,
        Message = "Signature validation successful")]
    public static partial void LogSignatureValidationSucceeded(
        this ILogger logger);

    [LoggerMessage(
        EventId = 2012,
        Level = LogLevel.Warning,
        Message = "Signature validation failed: {Reason}")]
    public static partial void LogSignatureValidationFailed(
        this ILogger logger,
        string reason);

    [LoggerMessage(
        EventId = 2020,
        Level = LogLevel.Debug,
        Message = "Digest validation started for {DisclosureCount} disclosures")]
    public static partial void LogDigestValidationStarted(
        this ILogger logger,
        int disclosureCount);

    [LoggerMessage(
        EventId = 2021,
        Level = LogLevel.Debug,
        Message = "Digest validation successful for all {ValidatedCount} disclosures")]
    public static partial void LogDigestValidationSucceeded(
        this ILogger logger,
        int validatedCount);

    [LoggerMessage(
        EventId = 2022,
        Level = LogLevel.Warning,
        Message = "Digest validation failed: {Reason}")]
    public static partial void LogDigestValidationFailed(
        this ILogger logger,
        string reason);

    [LoggerMessage(
        EventId = 2030,
        Level = LogLevel.Debug,
        Message = "Key resolution started for kid: {KeyId}")]
    public static partial void LogKeyResolutionStarted(
        this ILogger logger,
        string? keyId);

    [LoggerMessage(
        EventId = 2031,
        Level = LogLevel.Debug,
        Message = "Key resolution successful")]
    public static partial void LogKeyResolutionSucceeded(
        this ILogger logger);

    [LoggerMessage(
        EventId = 2032,
        Level = LogLevel.Error,
        Message = "Key resolution failed for kid: {KeyId}")]
    public static partial void LogKeyResolutionFailed(
        this ILogger logger,
        string? keyId);

    #endregion

    #region Presentation (3000-3999)

    [LoggerMessage(
        EventId = 3000,
        Level = LogLevel.Information,
        Message = "SD-JWT presentation started with {RequestedClaimCount} requested claims")]
    public static partial void LogPresentationStarted(
        this ILogger logger,
        int requestedClaimCount);

    [LoggerMessage(
        EventId = 3001,
        Level = LogLevel.Information,
        Message = "SD-JWT presentation completed with {IncludedDisclosureCount} disclosures")]
    public static partial void LogPresentationCompleted(
        this ILogger logger,
        int includedDisclosureCount);

    [LoggerMessage(
        EventId = 3002,
        Level = LogLevel.Debug,
        Message = "Claim path {ClaimPath} included in presentation")]
    public static partial void LogClaimIncluded(
        this ILogger logger,
        string claimPath);

    [LoggerMessage(
        EventId = 3003,
        Level = LogLevel.Debug,
        Message = "Claim path {ClaimPath} excluded from presentation")]
    public static partial void LogClaimExcluded(
        this ILogger logger,
        string claimPath);

    [LoggerMessage(
        EventId = 3004,
        Level = LogLevel.Error,
        Message = "SD-JWT presentation failed: {ErrorMessage}")]
    public static partial void LogPresentationFailed(
        this ILogger logger,
        Exception exception,
        string errorMessage);

    #endregion

    #region Key Binding (4000-4999)

    [LoggerMessage(
        EventId = 4000,
        Level = LogLevel.Debug,
        Message = "Key binding generation started")]
    public static partial void LogKeyBindingGenerationStarted(
        this ILogger logger);

    [LoggerMessage(
        EventId = 4001,
        Level = LogLevel.Debug,
        Message = "Key binding generated successfully using algorithm {Algorithm}")]
    public static partial void LogKeyBindingGenerated(
        this ILogger logger,
        string algorithm);

    [LoggerMessage(
        EventId = 4010,
        Level = LogLevel.Debug,
        Message = "Key binding validation started")]
    public static partial void LogKeyBindingValidationStarted(
        this ILogger logger);

    [LoggerMessage(
        EventId = 4011,
        Level = LogLevel.Debug,
        Message = "Key binding validation successful")]
    public static partial void LogKeyBindingValidationSucceeded(
        this ILogger logger);

    [LoggerMessage(
        EventId = 4012,
        Level = LogLevel.Warning,
        Message = "Key binding validation failed: {Reason}")]
    public static partial void LogKeyBindingValidationFailed(
        this ILogger logger,
        string reason);

    #endregion

    #region Cryptography (5000-5999)

    [LoggerMessage(
        EventId = 5000,
        Level = LogLevel.Debug,
        Message = "Signing operation started using {Algorithm}")]
    public static partial void LogSigningStarted(
        this ILogger logger,
        string algorithm);

    [LoggerMessage(
        EventId = 5001,
        Level = LogLevel.Debug,
        Message = "Signing operation completed")]
    public static partial void LogSigningCompleted(
        this ILogger logger);

    [LoggerMessage(
        EventId = 5002,
        Level = LogLevel.Error,
        Message = "Signing operation failed: {ErrorMessage}")]
    public static partial void LogSigningFailed(
        this ILogger logger,
        Exception exception,
        string errorMessage);

    [LoggerMessage(
        EventId = 5010,
        Level = LogLevel.Debug,
        Message = "Hash calculation started using {HashAlgorithm}")]
    public static partial void LogHashCalculationStarted(
        this ILogger logger,
        string hashAlgorithm);

    [LoggerMessage(
        EventId = 5011,
        Level = LogLevel.Debug,
        Message = "Hash calculation completed")]
    public static partial void LogHashCalculationCompleted(
        this ILogger logger);

    #endregion

    #region General (6000-6999)

    [LoggerMessage(
        EventId = 6000,
        Level = LogLevel.Warning,
        Message = "Security warning: {Message}")]
    public static partial void LogSecurityWarning(
        this ILogger logger,
        string message);

    [LoggerMessage(
        EventId = 6001,
        Level = LogLevel.Error,
        Message = "Unexpected error: {ErrorMessage}")]
    public static partial void LogUnexpectedError(
        this ILogger logger,
        Exception exception,
        string errorMessage);

    [LoggerMessage(
        EventId = 6002,
        Level = LogLevel.Debug,
        Message = "Configuration: {ConfigurationDetails}")]
    public static partial void LogConfiguration(
        this ILogger logger,
        string configurationDetails);

    #endregion
}
