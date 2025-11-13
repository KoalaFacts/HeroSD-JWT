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
    private readonly ConcurrentDictionary<string, TenantConfiguration> _tenants;
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte[]>> _tenantKeys;
    private readonly ILogger<TenantService> _logger;

    public TenantService(IConfiguration configuration, ILogger<TenantService> logger)
    {
        _logger = logger;
        _tenants = new ConcurrentDictionary<string, TenantConfiguration>(StringComparer.OrdinalIgnoreCase);
        _tenantKeys = new ConcurrentDictionary<string, ConcurrentDictionary<string, byte[]>>(StringComparer.OrdinalIgnoreCase);

        LoadTenantsFromConfiguration(configuration);
    }

    private void LoadTenantsFromConfiguration(IConfiguration configuration)
    {
        var tenantsSection = configuration.GetSection("MultiTenant:Tenants");
        var tenants = tenantsSection.Get<List<TenantConfiguration>>();

        if (tenants == null || tenants.Count == 0)
        {
            _logger.LogWarning("No tenants configured. Service will operate without tenant data.");
            return;
        }

        foreach (var tenant in tenants)
        {
            if (string.IsNullOrWhiteSpace(tenant.TenantId))
            {
                _logger.LogWarning("Skipping tenant with empty TenantId");
                continue;
            }

            _tenants[tenant.TenantId] = tenant;

            // Decode and cache signing keys
            var keyCache = new ConcurrentDictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (var (keyId, base64Key) in tenant.SigningKeys)
            {
                try
                {
                    var keyBytes = Convert.FromBase64String(base64Key);
                    keyCache[keyId] = keyBytes;
                    _logger.LogInformation(
                        "Loaded key {KeyId} for tenant {TenantId} ({KeySize} bytes)",
                        keyId, tenant.TenantId, keyBytes.Length);
                }
                catch (FormatException ex)
                {
                    _logger.LogError(ex,
                        "Failed to decode signing key {KeyId} for tenant {TenantId}",
                        keyId, tenant.TenantId);
                }
            }

            _tenantKeys[tenant.TenantId] = keyCache;

            _logger.LogInformation(
                "Registered tenant: {TenantId} ({TenantName}) with {KeyCount} key(s), current key: {CurrentKeyId}",
                tenant.TenantId, tenant.TenantName, keyCache.Count, tenant.CurrentKeyId);
        }
    }

    public TenantConfiguration? GetTenant(string tenantId)
    {
        _tenants.TryGetValue(tenantId, out var tenant);
        return tenant;
    }

    public IEnumerable<TenantConfiguration> GetAllTenants()
    {
        return _tenants.Values.Where(t => t.IsActive);
    }

    public byte[]? GetCurrentSigningKey(string tenantId)
    {
        var tenant = GetTenant(tenantId);
        if (tenant == null || !tenant.IsActive)
        {
            _logger.LogWarning("Attempted to get signing key for invalid/inactive tenant: {TenantId}", tenantId);
            return null;
        }

        return GetSigningKey(tenantId, tenant.CurrentKeyId);
    }

    public byte[]? GetSigningKey(string tenantId, string keyId)
    {
        if (!_tenantKeys.TryGetValue(tenantId, out var keys))
        {
            _logger.LogWarning("No keys found for tenant: {TenantId}", tenantId);
            return null;
        }

        if (!keys.TryGetValue(keyId, out var keyBytes))
        {
            _logger.LogWarning("Key {KeyId} not found for tenant {TenantId}", keyId, tenantId);
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
                _logger.LogDebug("Key resolver called with null keyId for tenant {TenantId}, using current key", tenantId);
                return GetCurrentSigningKey(tenantId);
            }

            var key = GetSigningKey(tenantId, keyId);
            if (key == null)
            {
                _logger.LogWarning(
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
