# HeroSD-JWT Operations Guide

**Production-Grade Operations Manual for HeroSD-JWT**

This comprehensive guide covers deployment, configuration, monitoring, and operational best practices for running HeroSD-JWT in production environments.

---

## Table of Contents

- [Quick Start Checklist](#quick-start-checklist)
- [Deployment Architecture](#deployment-architecture)
- [Configuration Management](#configuration-management)
- [Monitoring & Observability](#monitoring--observability)
- [Performance Tuning](#performance-tuning)
- [Security Hardening](#security-hardening)
- [High Availability](#high-availability)
- [Disaster Recovery](#disaster-recovery)
- [Troubleshooting](#troubleshooting)
- [Operational Runbooks](#operational-runbooks)

---

## Quick Start Checklist

### Pre-Production Deployment Checklist

- [ ] **Security**
  - [ ] Keys stored in secure key management system (Azure Key Vault, AWS KMS, etc.)
  - [ ] Strong signature algorithms configured (RS256, ES256, or EdDSA - never HS256 in production)
  - [ ] Clock skew configured appropriately (recommended: 5 minutes)
  - [ ] Key rotation schedule defined and documented
  - [ ] Security headers configured (if using ASP.NET Core)

- [ ] **Observability**
  - [ ] Logging configured with appropriate log levels
  - [ ] Metrics exported to monitoring system (Prometheus, Azure Monitor, etc.)
  - [ ] Distributed tracing enabled and configured
  - [ ] Alerts configured for critical failures
  - [ ] Dashboards created for key metrics

- [ ] **Performance**
  - [ ] Load testing completed under expected traffic
  - [ ] Performance benchmarks documented
  - [ ] Resource limits configured (memory, CPU)
  - [ ] Caching strategy implemented where appropriate

- [ ] **Reliability**
  - [ ] Health check endpoints configured
  - [ ] Circuit breaker patterns implemented for external dependencies
  - [ ] Graceful degradation strategy defined
  - [ ] Backup and recovery procedures documented

- [ ] **Compliance**
  - [ ] Data retention policies configured
  - [ ] Audit logging enabled for compliance requirements
  - [ ] GDPR/privacy considerations addressed
  - [ ] Security scan completed (NuGet audit, CodeQL, etc.)

---

## Deployment Architecture

### Recommended Deployment Patterns

#### Pattern 1: API Gateway with Centralized Verification

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ SD-JWT Presentation
       ▼
┌─────────────────────────────┐
│    API Gateway              │
│  ┌──────────────────────┐  │
│  │  HeroSD-JWT Verifier │  │ ◄── Verify all requests here
│  └──────────────────────┘  │
└──────────┬──────────────────┘
           │ Verified Claims
           ▼
┌─────────────────────────────┐
│   Microservices             │
│   (trust gateway claims)    │
└─────────────────────────────┘
```

**Pros:**
- Centralized security enforcement
- Simplified service implementation
- Consistent verification logic

**Cons:**
- Single point of failure (mitigate with HA)
- Added latency at gateway

#### Pattern 2: Distributed Verification

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ SD-JWT Presentation
       ├────────────────┬─────────────┐
       ▼                ▼             ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Service A  │  │  Service B  │  │  Service C  │
│  ┌────────┐ │  │  ┌────────┐ │  │  ┌────────┐ │
│  │Verifier│ │  │  │Verifier│ │  │  │Verifier│ │
│  └────────┘ │  │  └────────┘ │  │  └────────┘ │
└─────────────┘  └─────────────┘  └─────────────┘
```

**Pros:**
- No single point of failure
- Services remain independent
- Reduced gateway latency

**Cons:**
- Duplicate verification logic
- Harder to maintain consistency

#### Pattern 3: Hybrid (Recommended for Enterprise)

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ SD-JWT Presentation
       ▼
┌─────────────────────────────┐
│    API Gateway              │
│  - Rate limiting            │
│  - DDoS protection          │
│  - Basic JWT validation     │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│   Authorization Service     │
│  ┌──────────────────────┐  │
│  │  HeroSD-JWT Verifier │  │ ◄── Deep verification + caching
│  │  + Claims Cache       │  │
│  └──────────────────────┘  │
└──────────┬──────────────────┘
           │ Cached claims token
           ▼
┌─────────────────────────────┐
│   Microservices             │
└─────────────────────────────┘
```

**Pros:**
- Best security and performance
- Centralized verification with caching
- Defense in depth

---

## Configuration Management

### ASP.NET Core Configuration

#### appsettings.json (Development)

```json
{
  "SdJwt": {
    "Issuer": "https://issuer.example.com",
    "Audience": "api://my-api",
    "ClockSkew": "00:05:00",
    "RequireKeyBinding": true,
    "ExpectedHashAlgorithm": "sha-256",
    "TokenScheme": "Bearer",
    "SaveToken": false,
    "NameClaimType": "name",
    "RoleClaimType": "role"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "HeroSdJwt": "Debug",
      "Microsoft.AspNetCore": "Warning"
    }
  }
}
```

#### appsettings.Production.json

```json
{
  "SdJwt": {
    "Issuer": "https://issuer.production.com",
    "Audience": "api://production-api",
    "ClockSkew": "00:02:00",
    "RequireKeyBinding": true,
    "ExpectedHashAlgorithm": "sha-256",
    "TokenScheme": "Bearer",
    "SaveToken": false
  },
  "Logging": {
    "LogLevel": {
      "Default": "Warning",
      "HeroSdJwt": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  }
}
```

### Environment Variables (Kubernetes/Docker)

```bash
# Kubernetes Secret
apiVersion: v1
kind: Secret
metadata:
  name: sdjwt-secrets
type: Opaque
data:
  signing-key: <base64-encoded-key>
---
# ConfigMap for non-sensitive config
apiVersion: v1
kind: ConfigMap
metadata:
  name: sdjwt-config
data:
  SDJWT__Issuer: "https://issuer.production.com"
  SDJWT__Audience: "api://production-api"
  SDJWT__ClockSkew: "00:02:00"
  SDJWT__RequireKeyBinding: "true"
```

### Azure Key Vault Integration

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Add Azure Key Vault
if (builder.Environment.IsProduction())
{
    var keyVaultEndpoint = new Uri(builder.Configuration["KeyVault:Endpoint"]!);
    builder.Configuration.AddAzureKeyVault(
        keyVaultEndpoint,
        new DefaultAzureCredential());
}

// Configure SD-JWT
builder.Services.AddSdJwtAuthentication(options =>
{
    builder.Configuration.GetSection("SdJwt").Bind(options);

    // Key resolver using Azure Key Vault
    options.KeyResolver = async (kid, cancellationToken) =>
    {
        var keyClient = new KeyClient(keyVaultEndpoint, new DefaultAzureCredential());
        var key = await keyClient.GetKeyAsync(kid, cancellationToken: cancellationToken);
        return ConvertToJsonWebKey(key.Value);
    };
});
```

### AWS Secrets Manager Integration

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Add AWS Secrets Manager
if (builder.Environment.IsProduction())
{
    builder.Configuration.AddSecretsManager(region: RegionEndpoint.USEast1);
}

// Configure SD-JWT with AWS KMS
builder.Services.AddSdJwtAuthentication(options =>
{
    options.KeyResolver = async (kid, cancellationToken) =>
    {
        var kmsClient = new AmazonKeyManagementServiceClient(RegionEndpoint.USEast1);
        var publicKeyResponse = await kmsClient.GetPublicKeyAsync(new GetPublicKeyRequest
        {
            KeyId = kid
        }, cancellationToken);

        return ConvertToJsonWebKey(publicKeyResponse.PublicKey);
    };
});
```

---

## Monitoring & Observability

### Key Metrics to Monitor

#### Critical Business Metrics

| Metric | Description | Alert Threshold | Action |
|--------|-------------|-----------------|--------|
| `sdjwt.verification.count` | Total verifications | - | Track trend |
| `sdjwt.verification.failure.count` | Failed verifications | > 5% of total | Investigate immediately |
| `sdjwt.verification.duration` (p95) | 95th percentile latency | > 100ms | Performance investigation |
| `sdjwt.signature.failure.count` | Signature failures | > 1% of total | Security incident |
| `sdjwt.keybinding.failure.count` | Key binding failures | > 2% of total | Check key binding setup |

#### System Health Metrics

- **CPU Usage**: Alert if > 80% sustained for 5 minutes
- **Memory Usage**: Alert if > 85% sustained for 5 minutes
- **Request Rate**: Track requests per second
- **Error Rate**: Alert if > 1% error rate
- **Response Time**: Alert if p95 > 200ms

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'sdjwt-api'
    scrape_interval: 15s
    static_configs:
      - targets: ['api:8080']
    metrics_path: '/metrics'
```

### Grafana Dashboard (JSON)

```json
{
  "dashboard": {
    "title": "HeroSD-JWT Operations",
    "panels": [
      {
        "title": "Verification Success Rate",
        "targets": [
          {
            "expr": "rate(sdjwt_verification_count_total{result=\"success\"}[5m]) / rate(sdjwt_verification_count_total[5m]) * 100"
          }
        ]
      },
      {
        "title": "Verification Latency (p95)",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(sdjwt_verification_duration_bucket[5m]))"
          }
        ]
      },
      {
        "title": "Failure Breakdown",
        "targets": [
          {
            "expr": "sum by(failure_reason) (rate(sdjwt_verification_failure_count_total[5m]))"
          }
        ]
      }
    ]
  }
}
```

### Application Insights Queries (KQL)

```kql
// Verification failures by reason
traces
| where timestamp > ago(1h)
| where customDimensions.EventId >= 2000 and customDimensions.EventId < 3000
| where severityLevel >= 2  // Warning or Error
| summarize count() by tostring(customDimensions.FailureReason)
| order by count_ desc

// High latency verifications
traces
| where timestamp > ago(1h)
| where customDimensions.EventId == 2001  // Verification completed
| where customDimensions.Duration > 100  // > 100ms
| project timestamp, duration = todouble(customDimensions.Duration), disclosures = toint(customDimensions.DisclosureCount)
| order by duration desc

// Signature algorithm usage
traces
| where timestamp > ago(24h)
| where customDimensions.EventId == 1001  // Issuance completed
| summarize count() by tostring(customDimensions.Algorithm)
| render piechart
```

### Alert Rules

#### Critical Alerts (PagerDuty/On-Call)

```yaml
# Prometheus AlertManager rules
groups:
  - name: sdjwt_critical
    interval: 30s
    rules:
      - alert: HighVerificationFailureRate
        expr: |
          (
            rate(sdjwt_verification_failure_count_total[5m]) /
            rate(sdjwt_verification_count_total[5m])
          ) > 0.05
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High SD-JWT verification failure rate"
          description: "{{ $value | humanizePercentage }} of verifications failing"

      - alert: SignatureValidationFailureSpike
        expr: |
          rate(sdjwt_signature_failure_count_total[5m]) > 10
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Spike in signature validation failures"
          description: "Possible security incident or key rotation issue"

      - alert: HighVerificationLatency
        expr: |
          histogram_quantile(0.95, rate(sdjwt_verification_duration_bucket[5m])) > 200
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High SD-JWT verification latency"
          description: "P95 latency is {{ $value }}ms"
```

### Distributed Tracing

#### Jaeger Configuration

```csharp
// Program.cs
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing =>
    {
        tracing
            .AddSource(HeroSdJwtActivitySource.SourceName)
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddJaegerExporter(options =>
            {
                options.AgentHost = builder.Configuration["Jaeger:AgentHost"];
                options.AgentPort = int.Parse(builder.Configuration["Jaeger:AgentPort"]!);
            });
    });
```

#### Zipkin Configuration

```csharp
// Program.cs
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing =>
    {
        tracing
            .AddSource(HeroSdJwtActivitySource.SourceName)
            .AddZipkinExporter(options =>
            {
                options.Endpoint = new Uri(builder.Configuration["Zipkin:Endpoint"]!);
            });
    });
```

---

## Performance Tuning

### Expected Performance Baselines

| Operation | P50 | P95 | P99 |
|-----------|-----|-----|-----|
| Issuance (10 claims, 3 selective) | 45μs | 80μs | 120μs |
| Verification (HS256) | 50μs | 85μs | 130μs |
| Verification (RS256) | 200μs | 350μs | 500μs |
| Verification (ES256) | 150μs | 280μs | 420μs |
| Verification (EdDSA) | 130μs | 240μs | 380μs |
| Presentation creation | 10μs | 20μs | 35μs |

### Optimization Strategies

#### 1. Algorithm Selection

**Performance Hierarchy (fastest to slowest):**
1. **HS256** (HMAC) - ~50μs - Use for internal services only
2. **EdDSA** (Ed25519) - ~130μs - Best balance of speed and security
3. **ES256** (ECDSA P-256) - ~150μs - Good performance, widely supported
4. **RS256** (RSA 2048) - ~200μs - Slowest, but universally supported

**Recommendation:** Use **EdDSA (Ed25519)** for new deployments for optimal performance and security.

#### 2. Caching Strategies

##### Verification Result Caching

```csharp
// Cache verification results for short-lived tokens
services.AddMemoryCache();

public class CachedSdJwtVerifier
{
    private readonly ISdJwtVerifier _verifier;
    private readonly IMemoryCache _cache;

    public VerificationResult Verify(string presentation, JsonWebKey key)
    {
        // Use JWT signature as cache key (it's unique and deterministic)
        var cacheKey = $"sdjwt:verify:{ComputeHash(presentation)}";

        if (_cache.TryGetValue(cacheKey, out VerificationResult? cached))
        {
            return cached!;
        }

        var result = _verifier.TryVerifyPresentation(presentation, key);

        if (result.IsValid)
        {
            // Cache for 1 minute (adjust based on your security requirements)
            _cache.Set(cacheKey, result, TimeSpan.FromMinutes(1));
        }

        return result;
    }
}
```

##### Key Caching

```csharp
// Cache public keys to avoid repeated fetches from Key Vault
public class CachedKeyResolver
{
    private readonly IMemoryCache _cache;
    private readonly IKeyVaultClient _keyVault;

    public async Task<JsonWebKey?> ResolveKeyAsync(string kid, CancellationToken ct)
    {
        var cacheKey = $"sdjwt:key:{kid}";

        if (_cache.TryGetValue(cacheKey, out JsonWebKey? cached))
        {
            return cached;
        }

        var key = await _keyVault.GetPublicKeyAsync(kid, ct);

        if (key != null)
        {
            // Cache for 1 hour
            _cache.Set(cacheKey, key, TimeSpan.FromHours(1));
        }

        return key;
    }
}
```

#### 3. Resource Limits

```json
// appsettings.Production.json
{
  "Kestrel": {
    "Limits": {
      "MaxConcurrentConnections": 1000,
      "MaxConcurrentUpgradedConnections": 1000,
      "MaxRequestBodySize": 10485760,  // 10 MB
      "RequestHeadersTimeout": "00:00:30"
    }
  },
  "SdJwt": {
    "MaxDisclosures": 100,  // Prevent DoS with excessive disclosures
    "MaxClaimDepth": 10     // Prevent deeply nested objects
  }
}
```

#### 4. Connection Pooling

```csharp
// For key vault connections
services.AddHttpClient("KeyVault", client =>
{
    client.Timeout = TimeSpan.FromSeconds(10);
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    MaxConnectionsPerServer = 100  // Adjust based on load
});
```

---

## Security Hardening

### Production Security Checklist

#### Key Management

- [ ] **Never use HS256 in production** (symmetric keys are hard to distribute securely)
- [ ] **Use RS256, ES256, or EdDSA** for production deployments
- [ ] **Store keys in HSM or cloud KMS** (Azure Key Vault, AWS KMS, HashiCorp Vault)
- [ ] **Implement key rotation** (rotate keys every 90 days)
- [ ] **Use separate keys for each environment** (dev, staging, prod)
- [ ] **Implement key versioning** (kid claim with version identifier)
- [ ] **Secure key backup and recovery** procedures documented

#### Algorithm Configuration

```csharp
// ✅ GOOD - Explicit algorithm whitelist
options.VerificationOptions = new VerificationOptions
{
    ExpectedHashAlgorithm = "sha-256",
    AllowedSignatureAlgorithms = new[] { "RS256", "ES256", "EdDSA" }
};

// ❌ BAD - Allowing "none" or "HS256" in production
options.AllowedSignatureAlgorithms = new[] { "none", "HS256" };  // DON'T DO THIS!
```

#### Clock Skew

```csharp
// Production: Strict timing (2 minutes)
options.VerificationOptions = new VerificationOptions
{
    ClockSkew = TimeSpan.FromMinutes(2),
    RequireExpirationTime = true,
    RequireNotBefore = true
};

// Development: Lenient timing (5 minutes)
if (builder.Environment.IsDevelopment())
{
    options.VerificationOptions.ClockSkew = TimeSpan.FromMinutes(5);
}
```

#### Key Binding (Proof of Possession)

```csharp
// ALWAYS require key binding in production
options.RequireKeyBinding = true;

// Validate the key binding
options.KeyBindingValidator = (presentation, holderPublicKey) =>
{
    // Implement your key binding validation logic
    // This proves the presenter possesses the private key
    return ValidateKeyBindingJwt(presentation, holderPublicKey);
};
```

#### Rate Limiting

```csharp
// Add rate limiting to prevent brute force attacks
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("sdjwt", opt =>
    {
        opt.Window = TimeSpan.FromMinutes(1);
        opt.PermitLimit = 100;  // Max 100 verifications per minute per IP
        opt.QueueLimit = 0;
    });
});

app.UseRateLimiter();

// Apply to endpoints
app.MapGet("/verify", [RequireRateLimiting("sdjwt")] (HttpContext ctx) => { ... });
```

#### Security Headers

```csharp
// Add security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "no-referrer");
    context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");

    await next();
});
```

#### Audit Logging

```csharp
// Log all verification attempts for security auditing
public class SecurityAuditEnricher : ILogEnricher
{
    public void Enrich(LogEnrichmentContext context)
    {
        if (context.OperationType == "Verification")
        {
            // Extract claims from context
            context.AddProperty("AuditEvent", "SD-JWT Verification");
            context.AddProperty("Timestamp", DateTimeOffset.UtcNow);
            context.AddProperty("IPAddress", _httpContext.Connection.RemoteIpAddress?.ToString());
            context.AddProperty("UserAgent", _httpContext.Request.Headers.UserAgent.ToString());

            // Log to secure audit trail (tamper-proof storage)
            _auditLogger.LogSecurityEvent(context.Properties);
        }
    }
}
```

### Vulnerability Scanning

```bash
# Run NuGet security audit
dotnet list package --vulnerable --include-transitive

# Run CodeQL analysis
codeql database create sdjwt-db --language=csharp
codeql database analyze sdjwt-db csharp-security-and-quality.qls

# Run OWASP Dependency Check
dependency-check --project HeroSD-JWT --scan .
```

---

## High Availability

### Multi-Region Deployment

```yaml
# Azure Traffic Manager configuration
resource "azurerm_traffic_manager_profile" "sdjwt" {
  name                = "sdjwt-global"
  resource_group_name = azurerm_resource_group.main.name
  traffic_routing_method = "Performance"  # Route to nearest region

  dns_config {
    relative_name = "sdjwt-api"
    ttl           = 30
  }

  monitor_config {
    protocol = "HTTPS"
    port     = 443
    path     = "/health"
  }
}

resource "azurerm_traffic_manager_endpoint" "east_us" {
  name                = "east-us"
  resource_group_name = azurerm_resource_group.main.name
  profile_name        = azurerm_traffic_manager_profile.sdjwt.name
  type                = "azureEndpoints"
  target_resource_id  = azurerm_app_service.east_us.id
}

resource "azurerm_traffic_manager_endpoint" "west_eu" {
  name                = "west-eu"
  resource_group_name = azurerm_resource_group.main.name
  profile_name        = azurerm_traffic_manager_profile.sdjwt.name
  type                = "azureEndpoints"
  target_resource_id  = azurerm_app_service.west_eu.id
}
```

### Health Checks

```csharp
// Program.cs
builder.Services.AddHealthChecks()
    .AddCheck<SdJwtHealthCheck>("sdjwt")
    .AddCheck("memory", () =>
    {
        var allocated = GC.GetTotalMemory(false);
        var threshold = 1024L * 1024 * 1024 * 2;  // 2 GB
        return allocated < threshold
            ? HealthCheckResult.Healthy($"Memory: {allocated / 1024 / 1024} MB")
            : HealthCheckResult.Degraded($"Memory: {allocated / 1024 / 1024} MB");
    });

app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

// Custom health check
public class SdJwtHealthCheck : IHealthCheck
{
    private readonly ISdJwtVerifier _verifier;

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Test verification with a known-good token
            var testToken = "eyJ..."; // Known valid test token
            var result = _verifier.TryVerifyPresentation(testToken, _testKey);

            return result.IsValid
                ? HealthCheckResult.Healthy("SD-JWT verification operational")
                : HealthCheckResult.Degraded("SD-JWT verification failing");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("SD-JWT verification error", ex);
        }
    }
}
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sdjwt-api
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: sdjwt-api
  template:
    metadata:
      labels:
        app: sdjwt-api
    spec:
      containers:
      - name: api
        image: myregistry/sdjwt-api:v1.0.0
        ports:
        - containerPort: 8080
        env:
        - name: ASPNETCORE_ENVIRONMENT
          value: "Production"
        - name: SDJWT__Issuer
          valueFrom:
            configMapKeyRef:
              name: sdjwt-config
              key: issuer
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: sdjwt-api
spec:
  type: LoadBalancer
  ports:
  - port: 443
    targetPort: 8080
  selector:
    app: sdjwt-api
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: sdjwt-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sdjwt-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

---

## Disaster Recovery

### Backup Strategies

#### Key Material Backup

```bash
# Azure Key Vault backup
az keyvault key backup \
  --vault-name "production-kv" \
  --name "sdjwt-signing-key" \
  --file sdjwt-key-backup.blob

# Store backup in secure offline location
aws s3 cp sdjwt-key-backup.blob s3://disaster-recovery-bucket/keys/ \
  --sse aws:kms \
  --sse-kms-key-id alias/dr-key
```

#### Configuration Backup

```bash
# Export Kubernetes configs
kubectl get configmap sdjwt-config -o yaml > backups/sdjwt-config.yaml
kubectl get secret sdjwt-secrets -o yaml > backups/sdjwt-secrets.yaml

# Backup to version control (ensure secrets are encrypted!)
git-crypt unlock
cp backups/*.yaml infrastructure/kubernetes/production/
git add infrastructure/
git commit -m "Backup production configs"
git push
```

### Recovery Procedures

#### Scenario 1: Service Outage

```bash
# 1. Check health status
curl https://api.example.com/health

# 2. Check logs
kubectl logs -l app=sdjwt-api --tail=100

# 3. Restart pods
kubectl rollout restart deployment/sdjwt-api

# 4. Verify recovery
kubectl rollout status deployment/sdjwt-api
```

#### Scenario 2: Key Compromise

```bash
# IMMEDIATE ACTIONS (within minutes):

# 1. Rotate signing keys immediately
az keyvault key create \
  --vault-name "production-kv" \
  --name "sdjwt-signing-key-v2" \
  --kty RSA \
  --size 4096

# 2. Update key ID in configuration
kubectl set env deployment/sdjwt-api SDJWT__KeyId=sdjwt-signing-key-v2

# 3. Invalidate all existing tokens (if you have a revocation list)
# This depends on your implementation

# 4. Notify security team
# 5. Document incident for post-mortem
```

#### Scenario 3: Complete Region Failure

```bash
# 1. Fail over to secondary region
az traffic-manager endpoint update \
  --name "east-us" \
  --profile-name "sdjwt-global" \
  --resource-group "production" \
  --type azureEndpoints \
  --endpoint-status Disabled

# 2. Verify secondary region health
curl https://api-west-eu.example.com/health

# 3. Monitor traffic shift
# Check Azure Traffic Manager metrics

# 4. Once primary region recovers, re-enable
az traffic-manager endpoint update \
  --name "east-us" \
  --profile-name "sdjwt-global" \
  --resource-group "production" \
  --type azureEndpoints \
  --endpoint-status Enabled
```

---

## Troubleshooting

See the comprehensive [Troubleshooting Guide](troubleshooting.md) for detailed problem resolution.

### Quick Reference

| Issue | Quick Fix |
|-------|-----------|
| High verification failures | Check key rotation, clock skew, token expiration |
| High latency | Check algorithm (use EdDSA), enable caching, scale horizontally |
| Memory leaks | Check for unclosed Activity spans, review cache expiration |
| Signature failures | Verify key IDs match, check key rotation timing |
| Key binding failures | Ensure holder public key in JWT, validate KB-JWT format |

---

## Operational Runbooks

### Runbook 1: Key Rotation

**Frequency:** Every 90 days (scheduled)

**Steps:**

1. **Generate new key** (1 week before rotation date)
   ```bash
   az keyvault key create --vault-name prod-kv --name signing-key-v3 --kty EC --curve P-256
   ```

2. **Update issuer to sign with new key** (rotation date)
   ```csharp
   // Start issuing tokens with new key
   issuer.IssueToken(claims, newKey, kid: "signing-key-v3");
   ```

3. **Support both keys for verification** (overlap period: 24 hours)
   ```csharp
   options.KeyResolver = (kid, ct) =>
   {
       return kid switch
       {
           "signing-key-v2" => GetKey("signing-key-v2"),  // Old key
           "signing-key-v3" => GetKey("signing-key-v3"),  // New key
           _ => null
       };
   };
   ```

4. **Remove old key support** (after 24 hours)
   ```csharp
   options.KeyResolver = (kid, ct) => kid == "signing-key-v3" ? GetKey("signing-key-v3") : null;
   ```

5. **Archive old key** (keep for audit trail)
   ```bash
   az keyvault key backup --vault-name prod-kv --name signing-key-v2 --file backups/key-v2.bak
   ```

### Runbook 2: Incident Response - High Failure Rate

**Trigger:** Alert fires for > 5% verification failure rate

**Steps:**

1. **Acknowledge alert** and notify team
2. **Check metrics dashboard**
   - Is it signature failures, digest failures, or key binding failures?
   - What region/endpoint is affected?
3. **Check recent deployments**
   ```bash
   kubectl rollout history deployment/sdjwt-api
   ```
4. **Check key rotation logs**
   - Did a key rotation just happen?
   - Are old tokens being rejected?
5. **Check issuer service health**
   - Is the issuer generating malformed tokens?
6. **If needed, rollback**
   ```bash
   kubectl rollout undo deployment/sdjwt-api
   ```
7. **Document findings** in incident report

### Runbook 3: Scaling for High Traffic

**Trigger:** Expected traffic increase (e.g., product launch, Black Friday)

**Pre-Event Actions (1 week before):**

1. **Load test** with expected traffic
   ```bash
   k6 run --vus 1000 --duration 10m load-test.js
   ```

2. **Pre-scale infrastructure**
   ```bash
   kubectl scale deployment/sdjwt-api --replicas=10
   ```

3. **Warm up caches**
   ```bash
   # Pre-fetch keys into cache
   curl https://api.example.com/warmup
   ```

4. **Enable additional monitoring**
   ```bash
   # Increase Prometheus scrape frequency
   kubectl edit configmap prometheus-config
   ```

**During Event:**

1. Monitor dashboards continuously
2. Be ready to scale further if needed
3. Watch for anomalies (unexpected error patterns)

**Post-Event:**

1. **Scale down** gradually
   ```bash
   kubectl scale deployment/sdjwt-api --replicas=3
   ```

2. **Analyze metrics** and create report
3. **Update runbook** with learnings

---

## Summary

This operations guide provides a comprehensive foundation for running HeroSD-JWT in production. Key takeaways:

1. **Security First**: Use strong algorithms (EdDSA/ES256/RS256), secure key management, and require key binding
2. **Observability**: Implement comprehensive logging, metrics, and tracing from day one
3. **Performance**: Choose the right algorithm, implement caching, and set appropriate resource limits
4. **Reliability**: Deploy with high availability, health checks, and disaster recovery plans
5. **Continuous Improvement**: Monitor metrics, run regular drills, and update runbooks

For questions or issues:
- GitHub Issues: https://github.com/KoalaFacts/HeroSD-JWT/issues
- Discussions: https://github.com/KoalaFacts/HeroSD-JWT/discussions
