using MultiTenantAuthExample.Models;
using System.Collections.Concurrent;
using HeroSdJwt.Primitives;

namespace MultiTenantAuthExample.Services;

/// <summary>
/// Multi-tenant service managing tenant configurations and signing keys.
/// Supports key rotation with multiple active keys per tenant.
/// </summary>
public class TenantService : ITenantService
{
    private readonly ConcurrentDictionary<string, TenantConfiguration> tenants;
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte[]>> tenantKeys;
    private readonly ILogger<TenantService> logger;

    public TenantService(IConfiguration configuration, ILogger<TenantService> logger)
    {
        logger = logger;
        tenants = new ConcurrentDictionary<string, TenantConfiguration>(StringComparer.OrdinalIgnoreCase);
        tenantKeys = new ConcurrentDictionary<string, ConcurrentDictionary<string, byte[]>>(StringComparer.OrdinalIgnoreCase);

        LoadTenantsFromConfiguration(configuration);
    }

    private void LoadTenantsFromConfiguration(IConfiguration configuration)
    {
        var tenantsSection = configuration.GetSection("MultiTenant:Tenants");
        var tenants = tenantsSection.Get<List<TenantConfiguration>>();

        if (tenants == null || tenants.Count == 0)
        {
            logger.LogWarning("No tenants configured. Service will operate without tenant data.");
            return;
        }

        foreach (var tenant in tenants)
        {
            if (string.IsNullOrWhiteSpace(tenant.TenantId))
            {
                logger.LogWarning("Skipping tenant with empty TenantId");
                continue;
            }

            tenants[tenant.TenantId] = tenant;

            // Decode and cache signing keys
            var keyCache = new ConcurrentDictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (var (keyId, base64Key) in tenant.SigningKeys)
            {
                try
                {
                    var keyBytes = Convert.FromBase64String(base64Key);
                    keyCache[keyId] = keyBytes;
                    logger.LogInformation(
                        "Loaded key {KeyId} for tenant {TenantId} ({KeySize} bytes)",
                        keyId, tenant.TenantId, keyBytes.Length);
                }
                catch (FormatException ex)
                {
                    logger.LogError(ex,
                        "Failed to decode signing key {KeyId} for tenant {TenantId}",
                        keyId, tenant.TenantId);
                }
            }

            tenantKeys[tenant.TenantId] = keyCache;

            logger.LogInformation(
                "Registered tenant: {TenantId} ({TenantName}) with {KeyCount} key(s), current key: {CurrentKeyId}",
                tenant.TenantId, tenant.TenantName, keyCache.Count, tenant.CurrentKeyId);
        }
    }

    public TenantConfiguration? GetTenant(string tenantId)
    {
        tenants.TryGetValue(tenantId, out var tenant);
        return tenant;
    }

    public IEnumerable<TenantConfiguration> GetAllTenants()
    {
        return tenants.Values.Where(t => t.IsActive);
    }

    public byte[]? GetCurrentSigningKey(string tenantId)
    {
        var tenant = GetTenant(tenantId);
        if (tenant == null || !tenant.IsActive)
        {
            logger.LogWarning("Attempted to get signing key for invalid/inactive tenant: {TenantId}", tenantId);
            return null;
        }

        return GetSigningKey(tenantId, tenant.CurrentKeyId);
    }

    public byte[]? GetSigningKey(string tenantId, string keyId)
    {
        if (!tenantKeys.TryGetValue(tenantId, out var keys))
        {
            logger.LogWarning("No keys found for tenant: {TenantId}", tenantId);
            return null;
        }

        if (!keys.TryGetValue(keyId, out var keyBytes))
        {
            logger.LogWarning("Key {KeyId} not found for tenant {TenantId}", keyId, tenantId);
            return null;
        }

        return keyBytes;
    }

    public KeyResolver CreateKeyResolver(string tenantId)
    {
        // Return a delegate that resolves keys within the tenant scope
        return (string keyId) =>
        {
            if (string.IsNullOrEmpty(keyId))
            {
                logger.LogDebug("Key resolver called with null keyId for tenant {TenantId}, using current key", tenantId);
                return GetCurrentSigningKey(tenantId);
            }

            var key = GetSigningKey(tenantId, keyId);
            if (key == null)
            {
                logger.LogWarning(
                    "Key resolver failed to find key {KeyId} for tenant {TenantId}",
                    keyId, tenantId);
            }

            return key;
        };
    }

    public bool IsTenantValid(string tenantId)
    {
        var tenant = GetTenant(tenantId);
        return tenant != null && tenant.IsActive;
    }
}
