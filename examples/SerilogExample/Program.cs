using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Models;
using HeroSdJwt.Observability;
using HeroSdJwt.Presentation;
using HeroSdJwt.Verification;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

namespace SerilogExample;

/// <summary>
/// Comprehensive example demonstrating HeroSD-JWT observability with Serilog.
/// Shows logging, metrics, and distributed tracing in action.
/// </summary>
class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== HeroSD-JWT Observability with Serilog ===\n");

        // 1. Configure Serilog with rich formatting
        ConfigureSerilog();

        // 2. Set up metrics listener (optional - for demonstration)
        var metricsListener = SetupMetricsListener();

        // 3. Set up distributed tracing (optional - for demonstration)
        var activityListener = SetupDistributedTracing();

        // 4. Create loggers
        var loggerFactory = new LoggerFactory(new[] { new Serilog.Extensions.Logging.SerilogLoggerProvider() });
        var issuerLogger = loggerFactory.CreateLogger<SdJwtIssuer>();
        var verifierLogger = loggerFactory.CreateLogger<SdJwtVerifier>();
        var presenterLogger = loggerFactory.CreateLogger<SdJwtPresenter>();

        // 5. Optional: Add custom log enrichers
        AddCustomEnrichers();

        // 6. Run the full SD-JWT flow with observability
        RunSdJwtFlow(issuerLogger, verifierLogger, presenterLogger);

        // 7. Cleanup
        metricsListener?.Dispose();
        activityListener?.Dispose();
        Log.CloseAndFlush();

        Console.WriteLine("\n=== Example Complete ===");
        Console.WriteLine("Check 'logs/sdjwt-.log' for detailed logs");
    }

    static void ConfigureSerilog()
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", "HeroSD-JWT Example")
            .WriteTo.Console(
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} {Properties}{NewLine}{Exception}",
                restrictedToMinimumLevel: LogEventLevel.Information)
            .WriteTo.File(
                "logs/sdjwt-.log",
                rollingInterval: RollingInterval.Day,
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} {Level:u3}] [{SourceContext}] {Message:lj} {Properties}{NewLine}{Exception}",
                restrictedToMinimumLevel: LogEventLevel.Debug)
            .CreateLogger();

        Log.Information("Serilog configured successfully");
    }

    static MeterListener? SetupMetricsListener()
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == HeroSdJwtMetrics.MeterName)
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            }
        };

        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            var tagString = string.Join(", ", tags.ToArray().Select(t => $"{t.Key}={t.Value}"));
            Log.Information("[METRIC] {InstrumentName}: {Measurement} ({Tags})",
                instrument.Name, measurement, tagString);
        });

        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, state) =>
        {
            var tagString = string.Join(", ", tags.ToArray().Select(t => $"{t.Key}={t.Value}"));
            Log.Information("[METRIC] {InstrumentName}: {Measurement:F2}ms ({Tags})",
                instrument.Name, measurement, tagString);
        });

        listener.Start();
        Log.Information("Metrics listener started for {MeterName}", HeroSdJwtMetrics.MeterName);

        return listener;
    }

    static ActivityListener? SetupDistributedTracing()
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == HeroSdJwtActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> options) => ActivitySamplingResult.AllData,
            ActivityStarted = activity =>
            {
                Log.Debug("[TRACE] Activity started: {ActivityName} (TraceId: {TraceId}, SpanId: {SpanId})",
                    activity.DisplayName, activity.TraceId, activity.SpanId);
            },
            ActivityStopped = activity =>
            {
                var tags = string.Join(", ", activity.Tags.Select(t => $"{t.Key}={t.Value}"));
                Log.Debug("[TRACE] Activity completed: {ActivityName} - Duration: {Duration:F2}ms - Tags: [{Tags}]",
                    activity.DisplayName, activity.Duration.TotalMilliseconds, tags);
            }
        };

        ActivitySource.AddActivityListener(listener);
        Log.Information("Distributed tracing listener started for {SourceName}", HeroSdJwtActivitySource.SourceName);

        return listener;
    }

    static void AddCustomEnrichers()
    {
        // Example 1: Correlation ID Enricher
        LogEnricherCollection.Instance.Add(new CorrelationIdEnricher());

        // Example 2: Environment Enricher
        LogEnricherCollection.Instance.Add(new EnvironmentEnricher());

        Log.Information("Custom log enrichers registered: {EnricherCount}", LogEnricherCollection.Instance.Count);
    }

    static void RunSdJwtFlow(
        ILogger<SdJwtIssuer> issuerLogger,
        ILogger<SdJwtVerifier> verifierLogger,
        ILogger<SdJwtPresenter> presenterLogger)
    {
        Log.Information("\n=== Starting SD-JWT Flow ===");

        try
        {
            // Step 1: Issue SD-JWT
            Log.Information("\n--- Step 1: Issuing SD-JWT ---");
            var (sdJwt, key) = IssueSdJwt(issuerLogger);

            // Step 2: Create Presentation (Holder selects claims)
            Log.Information("\n--- Step 2: Creating Presentation ---");
            var presentation = CreatePresentation(sdJwt, presenterLogger);

            // Step 3: Verify Presentation
            Log.Information("\n--- Step 3: Verifying Presentation ---");
            VerifyPresentation(presentation, key, verifierLogger);

            // Step 4: Demonstrate verification failure (for logging)
            Log.Information("\n--- Step 4: Demonstrating Verification Failure ---");
            DemonstrateVerificationFailure(presentation, verifierLogger);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "SD-JWT flow failed with exception");
        }
    }

    static (SdJwt sdJwt, byte[] key) IssueSdJwt(ILogger<SdJwtIssuer> logger)
    {
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "name", "Alice Wonderland" },
            { "email", "alice@example.com" },
            { "age", 30 },
            { "address", new JsonObject
                {
                    { "street", "123 Main St" },
                    { "city", "Springfield" },
                    { "country", "USA" }
                }
            },
            { "roles", new[] { "admin", "user" } }
        };

        var key = RandomNumberGenerator.GetBytes(32); // 256-bit HMAC key

        Log.Information("Creating SD-JWT with {ClaimCount} claims", claims.Count);

        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email", "age", "address.city")  // Make specific claims selective
            .WithDecoys(2)  // Add privacy-enhancing decoys
            .SignWithHmac(key)
            .WithLogger(logger)  // 👈 Enable logging
            .Build();

        Log.Information("SD-JWT created with {DisclosureCount} disclosures", sdJwt.Disclosures.Count);
        Log.Debug("SD-JWT: {JwtPreview}...", sdJwt.Jwt[..Math.Min(50, sdJwt.Jwt.Length)]);

        return (sdJwt, key);
    }

    static string CreatePresentation(SdJwt sdJwt, ILogger<SdJwtPresenter> logger)
    {
        var presenter = new SdJwtPresenter(logger);  // 👈 Enable logging

        // Holder selects which claims to disclose to verifier
        var selectedClaims = new[] { "email", "address.city" };
        Log.Information("Holder selecting claims to disclose: {SelectedClaims}", string.Join(", ", selectedClaims));

        var presentation = presenter.CreatePresentation(sdJwt, selectedClaims);
        var formattedPresentation = presenter.FormatPresentation(presentation);

        Log.Information("Presentation created with {DisclosureCount} disclosures", presentation.SelectedDisclosures.Count);
        Log.Debug("Presentation format: JWT~{DisclosureCount} disclosures~KB", presentation.SelectedDisclosures.Count);

        return formattedPresentation;
    }

    static void VerifyPresentation(string presentation, byte[] key, ILogger<SdJwtVerifier> logger)
    {
        var options = new SdJwtVerificationOptions();
        var verifier = new SdJwtVerifier(
            options,
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(),
            new ClaimValidator(),
            logger);  // 👈 Enable logging

        Log.Information("Verifying presentation...");

        var result = verifier.TryVerifyPresentation(presentation, key);

        if (result.IsValid)
        {
            Log.Information("✓ Verification successful!");
            Log.Information("Disclosed claims:");
            foreach (var claim in result.DisclosedClaims)
            {
                Log.Information("  - {ClaimPath}: {ClaimValue}", claim.Key, claim.Value);
            }
        }
        else
        {
            Log.Warning("✗ Verification failed: {Errors}", string.Join(", ", result.Errors));
        }
    }

    static void DemonstrateVerificationFailure(string presentation, ILogger<SdJwtVerifier> logger)
    {
        var options = new SdJwtVerificationOptions();
        var verifier = new SdJwtVerifier(
            options,
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(),
            new ClaimValidator(),
            logger);

        // Use wrong key to demonstrate failure logging
        var wrongKey = RandomNumberGenerator.GetBytes(32);

        Log.Information("Attempting verification with incorrect key (to demonstrate error logging)...");

        var result = verifier.TryVerifyPresentation(presentation, wrongKey);

        Log.Warning("Expected verification failure: {ErrorCode}", result.Errors.FirstOrDefault());
    }
}

/// <summary>
/// Custom enricher that adds correlation IDs from Activity/TraceContext.
/// </summary>
public class CorrelationIdEnricher : ILogEnricher
{
    public void Enrich(LogEnrichmentContext context)
    {
        var currentActivity = Activity.Current;
        if (currentActivity != null)
        {
            context.AddProperty("TraceId", currentActivity.TraceId.ToString());
            context.AddProperty("SpanId", currentActivity.SpanId.ToString());

            // Add parent span if available
            if (currentActivity.ParentSpanId != default)
            {
                context.AddProperty("ParentSpanId", currentActivity.ParentSpanId.ToString());
            }
        }

        // Add a unique correlation ID for each operation
        context.AddProperty("CorrelationId", Guid.NewGuid().ToString("N")[..8]);
    }
}

/// <summary>
/// Custom enricher that adds environment information.
/// </summary>
public class EnvironmentEnricher : ILogEnricher
{
    public void Enrich(LogEnrichmentContext context)
    {
        context.AddProperty("MachineName", Environment.MachineName);
        context.AddProperty("ProcessId", Environment.ProcessId);

        // Add operation-specific metadata
        switch (context.OperationType)
        {
            case "SdJwtIssuer":
                context.AddProperty("OperationCategory", "Issuance");
                break;
            case "SdJwtVerifier":
                context.AddProperty("OperationCategory", "Verification");
                context.AddProperty("SecurityLevel", "Critical");  // Tag verification as security-critical
                break;
            case "SdJwtPresenter":
                context.AddProperty("OperationCategory", "Presentation");
                break;
        }
    }
}
