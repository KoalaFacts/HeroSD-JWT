# HeroSD-JWT Observability with Serilog - Example

This example demonstrates **comprehensive observability** in HeroSD-JWT using Serilog for structured logging, along with metrics and distributed tracing.

## 🚀 Quick Start

```bash
cd examples/SerilogExample
dotnet run
```

## 📋 What This Example Demonstrates

### 1. **Structured Logging with Serilog**
- Console output for high-level operations (Information level)
- File logging for detailed debugging (Debug level)
- Structured log events with semantic properties
- Custom log enrichment (correlation IDs, environment info)

### 2. **Metrics Collection**
- Real-time counters (issuance, verification, failures)
- Performance histograms (operation durations)
- Metrics printed to console during execution

### 3. **Distributed Tracing**
- Activity/Span creation for each operation
- TraceId and SpanId tracking
- Parent-child activity relationships
- Trace context propagation

### 4. **Custom Log Enrichers**
- **CorrelationIdEnricher**: Adds TraceId, SpanId, and correlation IDs
- **EnvironmentEnricher**: Adds machine name, process ID, and operation category

### 5. **Complete SD-JWT Flow**
- **Issue**: Create SD-JWT with selective disclosures and decoys
- **Present**: Holder selects which claims to disclose
- **Verify**: Verifier validates presentation (success case)
- **Error**: Demonstrates verification failure logging

## 📊 Expected Output

### Console Output (Information Level)
```
=== HeroSD-JWT Observability with Serilog ===

[12:34:56 INF] Serilog configured successfully
[12:34:56 INF] Metrics listener started for HeroSdJwt
[12:34:56 INF] Distributed tracing listener started for HeroSdJwt
[12:34:56 INF] Custom log enrichers registered: 2

=== Starting SD-JWT Flow ===

--- Step 1: Issuing SD-JWT ---
[12:34:56 INF] Creating SD-JWT with 6 claims
[12:34:56 INF] SD-JWT issuance started with 6 claims, 3 selective claims, 2 decoys
[12:34:56 INF] SD-JWT issued successfully with 3 disclosures using algorithm HS256
[12:34:56 INF] [METRIC] sdjwt.issuance.count: 1 (algorithm=HS256, hash_algorithm=Sha256)
[12:34:56 INF] [METRIC] sdjwt.issuance.duration: 12.50ms (algorithm=HS256)
[12:34:56 INF] SD-JWT created with 3 disclosures

--- Step 2: Creating Presentation ---
[12:34:56 INF] Holder selecting claims to disclose: email, address.city
[12:34:56 INF] SD-JWT presentation started with 2 requested claims
[12:34:56 INF] SD-JWT presentation completed with 2 disclosures
[12:34:56 INF] [METRIC] sdjwt.presentation.count: 1
[12:34:56 INF] [METRIC] sdjwt.presentation.duration: 3.20ms
[12:34:56 INF] Presentation created with 2 disclosures

--- Step 3: Verifying Presentation ---
[12:34:56 INF] Verifying presentation...
[12:34:56 INF] SD-JWT verification started
[12:34:56 INF] SD-JWT verification completed successfully with 2 disclosures
[12:34:56 INF] [METRIC] sdjwt.verification.count: 1 (result=success)
[12:34:56 INF] [METRIC] sdjwt.verification.duration: 8.75ms (result=success)
[12:34:56 INF] ✓ Verification successful!
[12:34:56 INF] Disclosed claims:
[12:34:56 INF]   - email: alice@example.com
[12:34:56 INF]   - address.city: Springfield

--- Step 4: Demonstrating Verification Failure ---
[12:34:56 INF] Attempting verification with incorrect key...
[12:34:56 INF] SD-JWT verification started
[12:34:56 WRN] SD-JWT verification failed with error code: InvalidSignature
[12:34:56 INF] [METRIC] sdjwt.verification.count: 1 (result=failure, error_code=InvalidSignature)
[12:34:56 INF] [METRIC] sdjwt.verification.failure.count: 1 (error_code=InvalidSignature)
[12:34:56 INF] [METRIC] sdjwt.verification.duration: 4.20ms (result=failure)
[12:34:56 WRN] Expected verification failure: InvalidSignature

=== Example Complete ===
Check 'logs/sdjwt-.log' for detailed logs
```

### File Output (Debug Level - logs/sdjwt-YYYYMMDD.log)

The log file contains **much more detail**, including:
- Individual disclosure generation events
- Decoy digest creation
- Signature validation steps
- Digest validation for each disclosure
- Complete trace context (TraceId, SpanId)
- Custom enriched properties

Example:
```
[2025-01-15 12:34:56.123 DBG] [HeroSdJwt.Issuance.SdJwtIssuer] Generated disclosure for claim path: email {TraceId="abc123", SpanId="def456", CorrelationId="1a2b3c4d"}
[2025-01-15 12:34:56.124 DBG] [HeroSdJwt.Issuance.SdJwtIssuer] Generated disclosure for claim path: age {TraceId="abc123", SpanId="def456", CorrelationId="1a2b3c4d"}
[2025-01-15 12:34:56.125 DBG] [HeroSdJwt.Issuance.SdJwtIssuer] Generated 2 decoy digests for privacy enhancement {TraceId="abc123", SpanId="def456"}
```

## 🎯 Key Observability Features Shown

### Structured Logging
```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email", "age")
    .SignWithHmac(key)
    .WithLogger(issuerLogger)  // 👈 Enable logging
    .Build();
```

### Custom Enrichers
```csharp
public class CorrelationIdEnricher : ILogEnricher
{
    public void Enrich(LogEnrichmentContext context)
    {
        context.AddProperty("TraceId", Activity.Current?.TraceId.ToString());
        context.AddProperty("CorrelationId", Guid.NewGuid().ToString("N")[..8]);
    }
}

LogEnricherCollection.Instance.Add(new CorrelationIdEnricher());
```

### Metrics Listener
```csharp
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
listener.Start();
```

### Distributed Tracing
```csharp
var listener = new ActivityListener
{
    ShouldListenTo = source => source.Name == HeroSdJwtActivitySource.SourceName,
    Sample = (ref ActivityCreationOptions<ActivityContext> options) => ActivitySamplingResult.AllData
};
ActivitySource.AddActivityListener(listener);
```

## 📁 Output Files

After running, you'll find:
```
examples/SerilogExample/
├── logs/
│   └── sdjwt-20250115.log  (detailed debug logs)
└── (console output)
```

## 🔧 Customization

### Change Log Levels

**Console (Information only):**
```csharp
.WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Information)
```

**File (Debug and above):**
```csharp
.WriteTo.File("logs/sdjwt-.log", restrictedToMinimumLevel: LogEventLevel.Debug)
```

### Add More Serilog Sinks

```csharp
.WriteTo.Seq("http://localhost:5341")  // Seq server
.WriteTo.Elasticsearch(...)             // Elasticsearch
.WriteTo.ApplicationInsights(...)       // Azure Application Insights
```

### Filter Specific Event IDs

```csharp
.Filter.ByIncludingOnly(evt =>
{
    // Only log verification events (2000-2999)
    return evt.Properties.ContainsKey("EventId") &&
           int.Parse(evt.Properties["EventId"].ToString()) >= 2000 &&
           int.Parse(evt.Properties["EventId"].ToString()) < 3000;
})
```

## 🏢 Production Recommendations

1. **Use appropriate log levels:**
   - `Debug`: Development only
   - `Information`: Key operations and metrics
   - `Warning`: Verification failures
   - `Error`: Unexpected errors

2. **Enable metrics in production:**
   - Export to Prometheus
   - Create Grafana dashboards
   - Set up alerting on failure rates

3. **Implement distributed tracing:**
   - Export to Jaeger, Zipkin, or Azure Monitor
   - Track SD-JWT flows across microservices
   - Correlate logs with traces

4. **Add custom enrichers:**
   - Tenant IDs for multi-tenant systems
   - User IDs for audit trails
   - Request IDs for correlation

5. **Security:**
   - Never log claim values or secrets
   - Review enricher implementations for PII
   - Use secure log storage

## 📚 Next Steps

- **Integrate with your application**: Add HeroSD-JWT logging to your existing Serilog setup
- **Set up dashboards**: Create Grafana dashboards from metrics
- **Enable OpenTelemetry**: Export traces to your APM system
- **Create alerts**: Alert on verification failure spikes

## 📖 Further Reading

- [HeroSD-JWT Observability Guide](../../docs/OBSERVABILITY.md)
- [Serilog Documentation](https://serilog.net/)
- [.NET Metrics Documentation](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/metrics)
- [OpenTelemetry .NET](https://opentelemetry.io/docs/languages/net/)
