using System.Diagnostics;

namespace HeroSdJwt.Observability;

/// <summary>
/// Provides distributed tracing support for HeroSD-JWT operations using System.Diagnostics.Activity.
/// </summary>
/// <remarks>
/// This ActivitySource enables OpenTelemetry and Application Performance Monitoring (APM) integration
/// for tracking SD-JWT operations across distributed systems.
/// <para>
/// To enable distributed tracing:
/// <code>
/// var listener = new ActivityListener
/// {
///     ShouldListenTo = source => source.Name == HeroSdJwtActivitySource.SourceName,
///     Sample = (ref ActivityCreationOptions&lt;ActivityContext&gt; options) => ActivitySamplingResult.AllData
/// };
/// ActivitySource.AddActivityListener(listener);
/// </code>
/// </para>
/// </remarks>
public static class HeroSdJwtActivitySource
{
    /// <summary>
    /// The name of the ActivitySource for HeroSD-JWT operations.
    /// </summary>
    public const string SourceName = "HeroSdJwt";

    /// <summary>
    /// The version of the ActivitySource (matches library version).
    /// </summary>
    public const string Version = "1.0.7";

    /// <summary>
    /// The ActivitySource instance for creating Activities.
    /// </summary>
    public static readonly ActivitySource Instance = new(SourceName, Version);

    /// <summary>
    /// Activity tag names used throughout the library.
    /// </summary>
    public static class Tags
    {
        /// <summary>Operation type (e.g., "issue", "verify", "present").</summary>
        public const string Operation = "sdjwt.operation";

        /// <summary>Number of claims in the SD-JWT.</summary>
        public const string ClaimCount = "sdjwt.claim_count";

        /// <summary>Number of selective disclosures.</summary>
        public const string DisclosureCount = "sdjwt.disclosure_count";

        /// <summary>Number of decoy digests.</summary>
        public const string DecoyCount = "sdjwt.decoy_count";

        /// <summary>Signature algorithm used.</summary>
        public const string Algorithm = "sdjwt.algorithm";

        /// <summary>Hash algorithm used.</summary>
        public const string HashAlgorithm = "sdjwt.hash_algorithm";

        /// <summary>Whether key binding is present.</summary>
        public const string HasKeyBinding = "sdjwt.has_key_binding";

        /// <summary>Verification result (success/failure).</summary>
        public const string VerificationResult = "sdjwt.verification_result";

        /// <summary>Error code if verification failed.</summary>
        public const string ErrorCode = "sdjwt.error_code";

        /// <summary>Key ID (kid) if present.</summary>
        public const string KeyId = "sdjwt.key_id";
    }
}
