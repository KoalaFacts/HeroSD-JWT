using System.Diagnostics.Metrics;

namespace HeroSdJwt.Observability;

/// <summary>
/// Provides metrics and counters for HeroSD-JWT operations using System.Diagnostics.Metrics.
/// </summary>
/// <remarks>
/// This Meter enables Prometheus, Application Insights, and other metrics collection systems
/// to track SD-JWT operation performance and health.
/// <para>
/// To enable metrics collection:
/// <code>
/// using var meterListener = new MeterListener
/// {
///     InstrumentPublished = (instrument, listener) =>
///     {
///         if (instrument.Meter.Name == HeroSdJwtMetrics.MeterName)
///         {
///             listener.EnableMeasurementEvents(instrument);
///         }
///     }
/// };
/// meterListener.Start();
/// </code>
/// </para>
/// </remarks>
public static class HeroSdJwtMetrics
{
    /// <summary>
    /// The name of the Meter for HeroSD-JWT operations.
    /// </summary>
    public const string MeterName = "HeroSdJwt";

    /// <summary>
    /// The version of the Meter (matches library version).
    /// </summary>
    public const string Version = "1.0.7";

    /// <summary>
    /// The Meter instance for creating instruments.
    /// </summary>
    public static readonly Meter Instance = new(MeterName, Version);

    // Counters

    /// <summary>
    /// Counter for the total number of SD-JWT issuance operations.
    /// </summary>
    public static readonly Counter<long> IssuanceCount = Instance.CreateCounter<long>(
        "sdjwt.issuance.count",
        description: "Total number of SD-JWT issuance operations");

    /// <summary>
    /// Counter for the total number of SD-JWT verification operations.
    /// </summary>
    public static readonly Counter<long> VerificationCount = Instance.CreateCounter<long>(
        "sdjwt.verification.count",
        description: "Total number of SD-JWT verification operations");

    /// <summary>
    /// Counter for the total number of SD-JWT presentation operations.
    /// </summary>
    public static readonly Counter<long> PresentationCount = Instance.CreateCounter<long>(
        "sdjwt.presentation.count",
        description: "Total number of SD-JWT presentation operations");

    /// <summary>
    /// Counter for the total number of failed verifications.
    /// </summary>
    public static readonly Counter<long> VerificationFailureCount = Instance.CreateCounter<long>(
        "sdjwt.verification.failure.count",
        description: "Total number of failed SD-JWT verifications");

    /// <summary>
    /// Counter for the total number of signature validation failures.
    /// </summary>
    public static readonly Counter<long> SignatureFailureCount = Instance.CreateCounter<long>(
        "sdjwt.signature.failure.count",
        description: "Total number of signature validation failures");

    /// <summary>
    /// Counter for the total number of digest validation failures.
    /// </summary>
    public static readonly Counter<long> DigestFailureCount = Instance.CreateCounter<long>(
        "sdjwt.digest.failure.count",
        description: "Total number of digest validation failures");

    /// <summary>
    /// Counter for the total number of key binding validation failures.
    /// </summary>
    public static readonly Counter<long> KeyBindingFailureCount = Instance.CreateCounter<long>(
        "sdjwt.keybinding.failure.count",
        description: "Total number of key binding validation failures");

    // Histograms

    /// <summary>
    /// Histogram for SD-JWT issuance operation duration in milliseconds.
    /// </summary>
    public static readonly Histogram<double> IssuanceDuration = Instance.CreateHistogram<double>(
        "sdjwt.issuance.duration",
        unit: "ms",
        description: "Duration of SD-JWT issuance operations in milliseconds");

    /// <summary>
    /// Histogram for SD-JWT verification operation duration in milliseconds.
    /// </summary>
    public static readonly Histogram<double> VerificationDuration = Instance.CreateHistogram<double>(
        "sdjwt.verification.duration",
        unit: "ms",
        description: "Duration of SD-JWT verification operations in milliseconds");

    /// <summary>
    /// Histogram for SD-JWT presentation operation duration in milliseconds.
    /// </summary>
    public static readonly Histogram<double> PresentationDuration = Instance.CreateHistogram<double>(
        "sdjwt.presentation.duration",
        unit: "ms",
        description: "Duration of SD-JWT presentation operations in milliseconds");

    // Gauges (using ObservableGauge for current values)

    /// <summary>
    /// Observable gauge for tracking the number of disclosures in the last issued SD-JWT.
    /// </summary>
    private static long lastDisclosureCount;

    /// <summary>
    /// Observable gauge for the number of disclosures in recently issued SD-JWTs.
    /// </summary>
    public static readonly ObservableGauge<long> DisclosureCount = Instance.CreateObservableGauge<long>(
        "sdjwt.disclosure.count",
        observeValue: () => lastDisclosureCount,
        description: "Number of disclosures in the last issued SD-JWT");

    /// <summary>
    /// Updates the last disclosure count for the observable gauge.
    /// </summary>
    /// <param name="count">The number of disclosures.</param>
    internal static void UpdateLastDisclosureCount(long count) => lastDisclosureCount = count;
}
