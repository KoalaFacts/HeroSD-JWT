# HeroSD-JWT Troubleshooting Guide

**Comprehensive Problem Resolution for HeroSD-JWT**

This guide helps you diagnose and resolve common issues when deploying and operating HeroSD-JWT in production.

---

## Table of Contents

- [Quick Diagnostic Tools](#quick-diagnostic-tools)
- [Verification Failures](#verification-failures)
- [Performance Issues](#performance-issues)
- [Authentication Problems](#authentication-problems)
- [Key Management Issues](#key-management-issues)
- [Observability Problems](#observability-problems)
- [Deployment Issues](#deployment-issues)
- [Common Error Messages](#common-error-messages)
- [Debugging Techniques](#debugging-techniques)

---

## Quick Diagnostic Tools

### Health Check Script

```bash
#!/bin/bash
# health-check.sh - Quick diagnostic script for HeroSD-JWT deployment

echo "=== HeroSD-JWT Health Check ==="

# 1. Check API availability
echo "[1/6] Checking API availability..."
if curl -s -f http://localhost:5000/health > /dev/null; then
    echo "✓ API is responding"
else
    echo "✗ API is not responding"
fi

# 2. Check logs for errors
echo "[2/6] Checking recent errors..."
ERROR_COUNT=$(kubectl logs -l app=sdjwt-api --tail=100 | grep -c ERROR || echo "0")
echo "Recent errors: $ERROR_COUNT"

# 3. Check metrics endpoint
echo "[3/6] Checking metrics..."
curl -s http://localhost:5000/metrics | grep sdjwt_verification_count || echo "✗ Metrics not available"

# 4. Check memory usage
echo "[4/6] Checking memory..."
kubectl top pod -l app=sdjwt-api

# 5. Check key vault connectivity
echo "[5/6] Checking Key Vault..."
az keyvault key show --vault-name "prod-kv" --name "signing-key" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Key Vault accessible"
else
    echo "✗ Key Vault not accessible"
fi

# 6. Test verification
echo "[6/6] Testing verification..."
curl -s -X POST http://localhost:5000/verify \
  -H "Content-Type: application/json" \
  -d '{"token":"test-token"}' | jq .

echo "=== Health Check Complete ==="
```

### Log Analysis Script

```bash
#!/bin/bash
# analyze-logs.sh - Analyze HeroSD-JWT logs for patterns

echo "=== Log Analysis ==="

# Get logs from last hour
kubectl logs -l app=sdjwt-api --since=1h > /tmp/sdjwt-logs.txt

# Count by error type
echo "Error distribution:"
grep "EventId:" /tmp/sdjwt-logs.txt | grep -E "EventId:(2[0-9]{3}|6[0-9]{3})" | \
  sed 's/.*EventId:\([0-9]*\).*/\1/' | sort | uniq -c | sort -rn

# Find slow verifications
echo -e "\nSlow verifications (>100ms):"
grep "EventId:2001" /tmp/sdjwt-logs.txt | grep -oP 'Duration=\K[0-9]+' | \
  awk '$1 > 100 {print $1 "ms"}' | head -10

# Find signature failures
echo -e "\nSignature failure reasons:"
grep "EventId:20[12]1" /tmp/sdjwt-logs.txt | grep "failed" || echo "None found"

# Summary
TOTAL=$(wc -l < /tmp/sdjwt-logs.txt)
ERRORS=$(grep -c ERROR /tmp/sdjwt-logs.txt)
WARNINGS=$(grep -c WARNING /tmp/sdjwt-logs.txt)

echo -e "\n=== Summary ==="
echo "Total log lines: $TOTAL"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"
echo "Error rate: $(awk "BEGIN {printf \"%.2f%%\", $ERRORS/$TOTAL*100}")"
```

---

## Verification Failures

### Problem: High verification failure rate

**Symptoms:**
- Alert: "High SD-JWT verification failure rate"
- Metrics: `sdjwt.verification.failure.count` increasing
- Users unable to access protected resources

**Diagnostic Steps:**

```bash
# 1. Check failure breakdown by type
kubectl logs -l app=sdjwt-api --tail=1000 | grep "EventId:2" | grep -i "fail"

# 2. Check metrics for specific failure types
curl -s http://localhost:5000/metrics | grep sdjwt_verification_failure_count

# 3. Check if it's a specific endpoint or global
kubectl logs -l app=sdjwt-api --tail=1000 | grep "verification failed" | \
  awk '{print $NF}' | sort | uniq -c
```

**Common Causes and Solutions:**

#### Cause 1: Clock Skew

**Symptoms:**
- Error: "Token expired" or "Token not yet valid"
- EventId: 2040 (temporal validation failed)

**Solution:**
```csharp
// Increase clock skew tolerance
builder.Services.AddSdJwtAuthentication(options =>
{
    options.VerificationOptions = new VerificationOptions
    {
        ClockSkew = TimeSpan.FromMinutes(5)  // Increase from 2 to 5 minutes
    };
});
```

**Verification:**
```bash
# Check time synchronization on servers
timedatectl status
# Ensure NTP is active and synchronized
```

#### Cause 2: Key Rotation Issues

**Symptoms:**
- Error: "Key not found for kid: xyz"
- EventId: 6010 (key resolution failed)
- Spike in failures after key rotation

**Solution:**
```csharp
// Support multiple keys during rotation period
builder.Services.AddSdJwtAuthentication(options =>
{
    options.KeyResolver = async (kid, ct) =>
    {
        // Support both old and new keys for 24 hours
        return kid switch
        {
            "key-v2" => await GetKeyFromVault("key-v2", ct),  // Old
            "key-v3" => await GetKeyFromVault("key-v3", ct),  // New
            _ => null
        };
    };

    // Set fallback key
    options.FallbackKey = await GetKeyFromVault("key-v3", ct);
});
```

#### Cause 3: Malformed Tokens from Issuer

**Symptoms:**
- Error: "Invalid JWT format"
- EventId: 6001 (parsing failed)
- Consistent failure rate across all tokens

**Diagnostic:**
```csharp
// Enable detailed logging to see token structure
builder.Services.AddLogging(logging =>
{
    logging.AddFilter("HeroSdJwt", LogLevel.Debug);
});

// In logs, look for:
// "SD-JWT verification started" - shows token structure
// "Disclosure parsing failed" - indicates malformed disclosures
```

**Solution:**
- Check issuer service logs for errors
- Validate issuer is using correct HeroSD-JWT version
- Test issuer output with manual verification:

```csharp
var token = "eyJ..."; // Token from issuer
var parts = token.Split('~');
Console.WriteLine($"JWT part: {parts[0]}");
Console.WriteLine($"Disclosure count: {parts.Length - 2}");
Console.WriteLine($"Key binding: {parts[^1]}");
```

#### Cause 4: Signature Algorithm Mismatch

**Symptoms:**
- Error: "Unsupported algorithm: XYZ"
- EventId: 6002 (algorithm validation failed)

**Solution:**
```csharp
// Ensure algorithm whitelist matches issuer
options.AllowedSignatureAlgorithms = new[] { "RS256", "ES256", "EdDSA" };

// Check what algorithm issuer is using
var jwt = token.Split('~')[0];
var header = JsonDocument.Parse(
    Base64UrlEncoder.DecodeString(jwt.Split('.')[0])
);
Console.WriteLine($"Token algorithm: {header.RootElement.GetProperty("alg").GetString()}");
```

### Problem: Specific claims not being disclosed

**Symptoms:**
- Users report missing data
- Claims expected but not in `result.DisclosedClaims`

**Diagnostic:**
```csharp
// Enable debug logging for disclosure processing
var logger = loggerFactory.CreateLogger<SdJwtVerifier>();
var result = verifier.TryVerifyPresentation(presentation, key, logger);

// Check logs for:
// EventId: 2020 - "Digest validation started for X disclosures"
// EventId: 2021 - "Digest validation successful for X disclosures"

// Verify disclosure count
Console.WriteLine($"Disclosures in presentation: {presentation.Split('~').Length - 2}");
Console.WriteLine($"Disclosures verified: {result.DisclosedClaims.Count}");
```

**Common Causes:**

1. **Holder didn't include disclosure in presentation**
   ```csharp
   // Solution: Check presentation creation
   var presentation = sdJwt.ToPresentation("email", "name", "age");
   // Make sure all required claims are listed
   ```

2. **Digest mismatch (tampered disclosure)**
   ```
   // Check logs for: EventId 2022 - "Digest mismatch for disclosure"
   // This indicates the disclosure was modified
   ```

3. **Nested claim path incorrect**
   ```csharp
   // For nested claims, use full path
   var presentation = sdJwt.ToPresentation("address.city", "address.zipcode");
   // Not just: "city", "zipcode"
   ```

---

## Performance Issues

### Problem: High verification latency (P95 > 200ms)

**Symptoms:**
- Alert: "High SD-JWT verification latency"
- Slow API response times
- Users experiencing delays

**Diagnostic:**
```bash
# Check latency distribution
curl -s http://localhost:5000/metrics | grep sdjwt_verification_duration

# Check for slow verifications in logs
kubectl logs -l app=sdjwt-api --tail=1000 | \
  grep "EventId:2001" | grep -oP 'Duration=\K[0-9]+' | \
  awk '{sum+=$1; count+=1} END {print "Avg: " sum/count "ms"}'
```

**Performance Analysis:**
```csharp
// Add custom timing logging
using var activity = HeroSdJwtActivitySource.Source.StartActivity("CustomVerification");
var sw = Stopwatch.StartNew();

var result = verifier.TryVerifyPresentation(presentation, key);

sw.Stop();
activity?.SetTag("duration_ms", sw.ElapsedMilliseconds);
_logger.LogInformation(
    "Verification took {Duration}ms for {DisclosureCount} disclosures using {Algorithm}",
    sw.ElapsedMilliseconds,
    result.DisclosedClaims.Count,
    algorithm);
```

**Solutions:**

#### Solution 1: Use Faster Algorithm

```csharp
// Algorithm performance comparison:
// EdDSA (Ed25519): ~130μs  ← Recommended
// ES256: ~150μs
// RS256: ~200μs
// HS256: ~50μs (but symmetric, avoid in production)

// Switch to EdDSA for best balance
var key = KeyGenerator.GenerateEd25519Key();
```

#### Solution 2: Implement Caching

```csharp
public class CachedSdJwtVerifier
{
    private readonly ISdJwtVerifier _verifier;
    private readonly IDistributedCache _cache;

    public async Task<VerificationResult> VerifyAsync(
        string presentation,
        JsonWebKey key,
        CancellationToken ct = default)
    {
        // Cache key: hash of presentation (deterministic)
        var cacheKey = $"sdjwt:v:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(presentation)))}";

        // Try cache first
        var cached = await _cache.GetStringAsync(cacheKey, ct);
        if (cached != null)
        {
            _logger.LogDebug("Cache hit for verification");
            return JsonSerializer.Deserialize<VerificationResult>(cached)!;
        }

        // Verify
        var result = _verifier.TryVerifyPresentation(presentation, key);

        // Cache if successful (cache for 5 minutes)
        if (result.IsValid)
        {
            await _cache.SetStringAsync(
                cacheKey,
                JsonSerializer.Serialize(result),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
                },
                ct);
        }

        return result;
    }
}
```

#### Solution 3: Optimize Key Resolution

```csharp
// Cache keys to avoid repeated Key Vault calls
public class CachedKeyResolver
{
    private readonly IMemoryCache _cache;
    private readonly IKeyVaultClient _keyVault;

    public async Task<JsonWebKey?> ResolveAsync(string kid, CancellationToken ct)
    {
        return await _cache.GetOrCreateAsync(
            $"key:{kid}",
            async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1);
                return await _keyVault.GetPublicKeyAsync(kid, ct);
            });
    }
}

// Use cached resolver
builder.Services.AddSingleton<CachedKeyResolver>();
builder.Services.AddSdJwtAuthentication(options =>
{
    var keyResolver = app.Services.GetRequiredService<CachedKeyResolver>();
    options.KeyResolver = keyResolver.ResolveAsync;
});
```

#### Solution 4: Scale Horizontally

```bash
# Increase replica count
kubectl scale deployment/sdjwt-api --replicas=5

# Or enable auto-scaling
kubectl autoscale deployment/sdjwt-api --min=3 --max=10 --cpu-percent=70
```

### Problem: Memory leaks

**Symptoms:**
- Memory usage continuously increasing
- OOM kills in Kubernetes
- GC spending too much time

**Diagnostic:**
```bash
# Check memory usage trend
kubectl top pod -l app=sdjwt-api

# Get memory dump for analysis
kubectl exec -it sdjwt-api-pod -- \
  dotnet-gcdump collect -p 1 -o /tmp/dump.gcdump

# Download and analyze with Visual Studio or dotnet-dump
kubectl cp sdjwt-api-pod:/tmp/dump.gcdump ./dump.gcdump
dotnet-gcdump report dump.gcdump
```

**Common Causes:**

#### Cause 1: Activity not disposed

```csharp
// ❌ BAD - Activity never disposed
var activity = HeroSdJwtActivitySource.Source.StartActivity("Verify");
var result = verifier.TryVerifyPresentation(token, key);
// Activity leaked!

// ✅ GOOD - Use using statement
using var activity = HeroSdJwtActivitySource.Source.StartActivity("Verify");
var result = verifier.TryVerifyPresentation(token, key);
```

#### Cause 2: Cache entries never expiring

```csharp
// ❌ BAD - No expiration
_cache.Set(key, value);

// ✅ GOOD - Always set expiration
_cache.Set(key, value, new MemoryCacheEntryOptions
{
    SlidingExpiration = TimeSpan.FromMinutes(10),
    Size = 1  // For size-based eviction
});

// Configure cache size limits
services.AddMemoryCache(options =>
{
    options.SizeLimit = 1024;  // Max 1024 entries
    options.CompactionPercentage = 0.25;  // Compact 25% when full
});
```

#### Cause 3: Logger scope not disposed

```csharp
// ❌ BAD
var scope = _logger.BeginScope(new Dictionary<string, object> { ["TenantId"] = tenantId });

// ✅ GOOD
using var scope = _logger.BeginScope(new Dictionary<string, object> { ["TenantId"] = tenantId });
```

---

## Authentication Problems

### Problem: 401 Unauthorized responses

**Symptoms:**
- All requests returning 401
- Error: "No SD-JWT token found in Authorization header"

**Diagnostic:**
```bash
# Test with curl to see exact response
curl -v -H "Authorization: Bearer eyJ..." https://api.example.com/protected

# Check authentication handler logs
kubectl logs -l app=sdjwt-api | grep "SdJwtAuthenticationHandler"
```

**Common Causes:**

#### Cause 1: Wrong token scheme

```csharp
// Check token scheme configuration
builder.Services.AddSdJwtAuthentication(options =>
{
    options.TokenScheme = "Bearer";  // Default is "Bearer"
});

// Ensure client sends: Authorization: Bearer <token>
// Not: Authorization: Token <token>
```

#### Cause 2: Token not reaching handler

```csharp
// Verify middleware order
app.UseAuthentication();  // Must be BEFORE UseAuthorization
app.UseAuthorization();

// Debug middleware by adding logging
app.Use(async (context, next) =>
{
    var auth = context.Request.Headers.Authorization.ToString();
    Console.WriteLine($"Authorization header: {auth}");
    await next();
});
```

#### Cause 3: Authentication not configured

```csharp
// Ensure authentication is added
builder.Services
    .AddAuthentication(SdJwtAuthenticationDefaults.AuthenticationScheme)
    .AddSdJwt(options => { /* config */ });

// And used in pipeline
app.UseAuthentication();
```

### Problem: 403 Forbidden with valid token

**Symptoms:**
- Token verifies successfully
- But user gets 403 Forbidden
- Authorization is failing

**Diagnostic:**
```csharp
// Check claims in token
app.MapGet("/debug-claims", (HttpContext ctx) =>
{
    var identity = ctx.User.Identity as ClaimsIdentity;
    var claims = identity?.Claims.Select(c => new { c.Type, c.Value }).ToList();
    return Results.Json(claims);
}).RequireAuthorization();

// Check authorization policy
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AdminOnly", policy =>
    {
        policy.RequireClaim("role", "admin");  // Check this matches token
    });
```

**Solution:**
```csharp
// Ensure claim type mapping is correct
builder.Services.AddSdJwtAuthentication(options =>
{
    options.NameClaimType = "name";  // Or "sub", depends on your token
    options.RoleClaimType = "role";  // Ensure this matches your JWT
});

// Check what claims are in the token
var jwt = token.Split('~')[0];
var payload = JsonDocument.Parse(
    Base64UrlEncoder.DecodeString(jwt.Split('.')[1])
);
Console.WriteLine(payload.RootElement.GetRawText());
```

---

## Key Management Issues

### Problem: Key Vault connectivity failures

**Symptoms:**
- Error: "Key not found" or "Unauthorized"
- EventId: 6010
- Intermittent verification failures

**Diagnostic:**
```bash
# Test Key Vault connectivity
az keyvault key show \
  --vault-name "production-kv" \
  --name "signing-key" \
  --query "key.kid"

# Check managed identity permissions
az keyvault show --name "production-kv" --query "properties.accessPolicies"

# Test from pod
kubectl exec -it sdjwt-api-pod -- \
  curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
```

**Solutions:**

#### Solution 1: Grant Managed Identity Access

```bash
# Get pod's managed identity
MI_PRINCIPAL_ID=$(az identity show \
  --name "sdjwt-identity" \
  --resource-group "production" \
  --query principalId -o tsv)

# Grant Key Vault access
az keyvault set-policy \
  --name "production-kv" \
  --object-id $MI_PRINCIPAL_ID \
  --key-permissions get list \
  --secret-permissions get list
```

#### Solution 2: Implement Retry Logic

```csharp
public class ResilientKeyResolver
{
    private readonly IKeyVaultClient _keyVault;
    private readonly ILogger<ResilientKeyResolver> _logger;

    public async Task<JsonWebKey?> ResolveAsync(string kid, CancellationToken ct)
    {
        var retryPolicy = Policy
            .Handle<HttpRequestException>()
            .Or<TimeoutException>()
            .WaitAndRetryAsync(
                retryCount: 3,
                sleepDurationProvider: attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)),
                onRetry: (exception, timeSpan, attempt, context) =>
                {
                    _logger.LogWarning(
                        exception,
                        "Key resolution attempt {Attempt} failed, retrying in {Delay}s",
                        attempt,
                        timeSpan.TotalSeconds);
                });

        return await retryPolicy.ExecuteAsync(async () =>
        {
            return await _keyVault.GetPublicKeyAsync(kid, ct);
        });
    }
}
```

#### Solution 3: Implement Fallback Key

```csharp
// Always configure a fallback key for resilience
builder.Services.AddSdJwtAuthentication(options =>
{
    options.KeyResolver = ResolveKeyFromVault;

    // Fallback key from local configuration (for disasters)
    var fallbackKeyJson = builder.Configuration["SdJwt:FallbackKey"];
    if (!string.IsNullOrEmpty(fallbackKeyJson))
    {
        options.FallbackKey = JsonSerializer.Deserialize<JsonWebKey>(fallbackKeyJson);
    }
});
```

### Problem: Key rotation causing outage

**Symptoms:**
- Spike in 401 errors after key rotation
- Error: "Key not found for kid: new-key-id"

**Solution:**
```csharp
// Implement overlapping key support during rotation
public class RotationAwareKeyResolver
{
    private readonly IKeyVaultClient _keyVault;
    private readonly IMemoryCache _cache;

    public async Task<JsonWebKey?> ResolveAsync(string kid, CancellationToken ct)
    {
        // Cache keys for 5 minutes during rotation
        var cacheKey = $"key:{kid}";

        if (_cache.TryGetValue(cacheKey, out JsonWebKey? cached))
        {
            return cached;
        }

        // Try to get key from vault
        var key = await _keyVault.GetPublicKeyAsync(kid, ct);

        if (key != null)
        {
            // Cache for 5 minutes
            _cache.Set(cacheKey, key, TimeSpan.FromMinutes(5));
        }

        return key;
    }
}

// Use in configuration
builder.Services.AddSdJwtAuthentication(options =>
{
    var resolver = new RotationAwareKeyResolver(keyVault, cache);
    options.KeyResolver = resolver.ResolveAsync;
});
```

**Rotation Checklist:**
1. Generate new key in Key Vault
2. Update issuer to use new key (but keep old key ID in cache)
3. Wait 24 hours (or longest token lifetime)
4. Remove old key from Key Vault
5. Clear cache of old key

---

## Observability Problems

### Problem: Logs not appearing

**Symptoms:**
- No logs in log aggregation system
- Metrics not being collected
- Can't diagnose issues

**Diagnostic:**
```csharp
// Test if logging is configured
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("Test log message");

// Check log level configuration
var config = app.Services.GetRequiredService<IConfiguration>();
Console.WriteLine($"Log level: {config["Logging:LogLevel:HeroSdJwt"]}");
```

**Solutions:**

#### Solution 1: Configure Logging Provider

```csharp
// Ensure logging provider is added
builder.Services.AddLogging(logging =>
{
    logging.ClearProviders();
    logging.AddConsole();
    logging.AddDebug();
    logging.AddApplicationInsights();  // If using App Insights
    logging.SetMinimumLevel(LogLevel.Information);

    // Enable HeroSD-JWT logs
    logging.AddFilter("HeroSdJwt", LogLevel.Debug);
});
```

#### Solution 2: Pass Logger to Components

```csharp
// HeroSD-JWT requires explicit logger passing
var logger = loggerFactory.CreateLogger<SdJwtVerifier>();

// ❌ BAD - No logger
var result = verifier.TryVerifyPresentation(token, key);

// ✅ GOOD - With logger
var result = verifier.TryVerifyPresentation(token, key, logger);
```

### Problem: Metrics not exported

**Symptoms:**
- Prometheus scraping returns 404
- Grafana dashboards empty

**Solution:**
```csharp
// Add metrics endpoint
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics
            .AddMeter(HeroSdJwtMetrics.MeterName)
            .AddPrometheusExporter();
    });

// Map metrics endpoint
app.MapPrometheusScrapingEndpoint("/metrics");

// Verify endpoint
// curl http://localhost:5000/metrics | grep sdjwt
```

### Problem: Traces not appearing in tracing backend

**Diagnostic:**
```csharp
// Check if Activity Source is registered
var listener = new ActivityListener
{
    ShouldListenTo = source => source.Name == HeroSdJwtActivitySource.SourceName,
    Sample = (ref ActivityCreationOptions<ActivityContext> options) => ActivitySamplingResult.AllData,
    ActivityStarted = activity => Console.WriteLine($"Activity started: {activity.DisplayName}"),
    ActivityStopped = activity => Console.WriteLine($"Activity stopped: {activity.DisplayName}")
};

ActivitySource.AddActivityListener(listener);
```

**Solution:**
```csharp
// Ensure OpenTelemetry is configured
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing =>
    {
        tracing
            .AddSource(HeroSdJwtActivitySource.SourceName)  // ← Add this!
            .AddAspNetCoreInstrumentation()
            .AddJaegerExporter(options =>
            {
                options.AgentHost = "jaeger";
                options.AgentPort = 6831;
            });
    });
```

---

## Deployment Issues

### Problem: Container fails to start

**Symptoms:**
- Kubernetes pod in CrashLoopBackOff
- Container exits immediately

**Diagnostic:**
```bash
# Check pod status
kubectl get pods -l app=sdjwt-api

# Check pod events
kubectl describe pod sdjwt-api-pod

# Check container logs
kubectl logs sdjwt-api-pod --previous

# Check startup probe
kubectl get pod sdjwt-api-pod -o jsonpath='{.status.containerStatuses[0]}'
```

**Common Causes:**

#### Cause 1: Missing environment variables

```yaml
# Kubernetes deployment - ensure all required env vars are set
env:
- name: SDJWT__Issuer
  valueFrom:
    configMapKeyRef:
      name: sdjwt-config
      key: issuer
- name: ASPNETCORE_ENVIRONMENT
  value: "Production"
```

#### Cause 2: Health check failing

```csharp
// Ensure health check endpoint exists
app.MapHealthChecks("/health/live");
app.MapHealthChecks("/health/ready");

// Check health check configuration
builder.Services.AddHealthChecks()
    .AddCheck("self", () => HealthCheckResult.Healthy());
```

#### Cause 3: Port mismatch

```yaml
# Ensure Dockerfile exposes correct port
EXPOSE 8080

# And Kubernetes service targets correct port
spec:
  ports:
  - port: 443
    targetPort: 8080  # Must match EXPOSE
```

---

## Common Error Messages

### "InvalidJwtFormat: Token must have 3 parts separated by dots"

**Meaning:** The JWT portion is malformed

**Solution:**
```csharp
// Verify token structure
var token = "your-token-here";
var parts = token.Split('~');
Console.WriteLine($"SD-JWT parts: {parts.Length}");  // Should be 3+
Console.WriteLine($"JWT: {parts[0]}");
Console.WriteLine($"JWT parts: {parts[0].Split('.').Length}");  // Should be 3
```

### "SignatureValidationFailed: Signature verification failed"

**Meaning:** Signature doesn't match the key

**Causes:**
1. Wrong key used for verification
2. Token was tampered with
3. Key ID (kid) mismatch

**Solution:**
```csharp
// Verify key ID matches
var jwt = token.Split('~')[0];
var header = JsonDocument.Parse(Base64UrlEncoder.DecodeString(jwt.Split('.')[0]));
var kid = header.RootElement.GetProperty("kid").GetString();
Console.WriteLine($"Token kid: {kid}");
Console.WriteLine($"Verifying key kid: {key.KeyId}");
// These must match!
```

### "DigestMismatch: Disclosure digest does not match"

**Meaning:** Disclosure was tampered with or corrupted

**Solution:**
- Token has been modified in transit
- Check for encoding issues (URL encoding, base64 padding)
- Verify token hasn't been truncated

```csharp
// Verify disclosure integrity
var disclosures = token.Split('~').Skip(1).TakeWhile(s => !string.IsNullOrEmpty(s));
foreach (var disclosure in disclosures)
{
    try
    {
        var decoded = Base64UrlEncoder.DecodeString(disclosure);
        Console.WriteLine($"Disclosure OK: {decoded}");
    }
    catch
    {
        Console.WriteLine($"Disclosure corrupted: {disclosure}");
    }
}
```

### "KeyBindingValidationFailed: Key binding JWT validation failed"

**Meaning:** Holder proof of possession failed

**Causes:**
1. KB-JWT signature invalid
2. Holder public key mismatch
3. KB-JWT expired

**Solution:**
```csharp
// Enable detailed KB validation logging
var logger = loggerFactory.CreateLogger("KeyBinding");
logger.LogDebug("Validating key binding...");

// Check KB-JWT structure
var kbJwt = token.Split('~').Last();
if (string.IsNullOrEmpty(kbJwt))
{
    logger.LogError("No key binding JWT found in presentation");
}
```

---

## Debugging Techniques

### Enable Verbose Logging

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "HeroSdJwt": "Trace",  // ← Maximum verbosity
      "System.Net.Http": "Debug"
    }
  }
}
```

### Use Fiddler/HTTP Proxy

```bash
# Set proxy environment variables
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888

# Run application
dotnet run
```

### Attach Debugger to Running Container

```bash
# For .NET debugging in Kubernetes
kubectl port-forward sdjwt-api-pod 5000:5000

# In VS Code, attach to process
# Or use: dotnet attach <pid>
```

### Performance Profiling

```bash
# Collect CPU profile
dotnet-trace collect --process-id <pid> --profile cpu-sampling

# Collect memory profile
dotnet-gcdump collect --process-id <pid>

# Analyze with PerfView or dotnet-trace
dotnet-trace analyze trace.nettrace
```

---

## Getting Help

If you're still stuck after trying these solutions:

1. **Search GitHub Issues**: https://github.com/KoalaFacts/HeroSD-JWT/issues
2. **Ask in Discussions**: https://github.com/KoalaFacts/HeroSD-JWT/discussions
3. **File a Bug Report**: Include:
   - HeroSD-JWT version
   - .NET version
   - Complete error message and stack trace
   - Minimal reproduction code
   - Relevant logs (with sensitive data redacted)

---

## Appendix: Diagnostic Checklist

When reporting issues, please provide:

- [ ] HeroSD-JWT version (NuGet package version)
- [ ] .NET version (`dotnet --version`)
- [ ] Operating system and version
- [ ] Deployment environment (local, Docker, Kubernetes, Azure, AWS, etc.)
- [ ] Complete error message and stack trace
- [ ] Relevant configuration (with secrets redacted)
- [ ] Log output (with sensitive data redacted)
- [ ] Steps to reproduce
- [ ] Expected vs actual behavior
- [ ] Metrics showing the issue (if applicable)

This helps maintainers diagnose and resolve issues quickly!
