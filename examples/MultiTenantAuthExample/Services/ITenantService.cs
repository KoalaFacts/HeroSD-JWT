using MultiTenantAuthExample.Models;

namespace MultiTenantAuthExample.Services;

/// <summary>
/// Service interface for managing multi-tenant operations.
/// </summary>
public interface ITenantService
{
    /// <summary>
    /// Gets configuration for a specific tenant.
    /// </summary>
    TenantConfiguration? GetTenant(string tenantId);

    /// <summary>
    /// Gets all configured tenants.
    /// </summary>
    IEnumerable<TenantConfiguration> GetAllTenants();

    /// <summary>
    /// Gets the current signing key bytes for a tenant.
    /// </summary>
    byte[]? GetCurrentSigningKey(string tenantId);

    /// <summary>
    /// Gets a specific signing key by tenant ID and key ID.
    /// </summary>
    byte[]? GetSigningKey(string tenantId, string keyId);

    /// <summary>
    /// Creates a key resolver delegate for multi-tenant key resolution.
    /// Supports the tenant isolation pattern where keys are scoped per tenant.
    /// </summary>
    HeroSdJwt.Primitives.KeyResolver CreateKeyResolver(string tenantId);

    /// <summary>
    /// Validates that a tenant exists and is active.
    /// </summary>
    bool IsTenantValid(string tenantId);
}
