namespace MultiTenantAuthExample.Models;

/// <summary>
/// Configuration for a single tenant including signing keys and metadata.
/// </summary>
public class TenantConfiguration
{
    /// <summary>
    /// Unique tenant identifier (e.g., "acme-corp", "contoso").
    /// </summary>
    public required string TenantId { get; init; }

    /// <summary>
    /// Human-readable tenant name.
    /// </summary>
    public required string TenantName { get; init; }

    /// <summary>
    /// Current active signing key for issuing new tokens.
    /// </summary>
    public required string CurrentKeyId { get; init; }

    /// <summary>
    /// All valid signing keys for this tenant (current + rotated keys still in grace period).
    /// Key: keyId, Value: Base64-encoded key bytes.
    /// </summary>
    public required Dictionary<string, string> SigningKeys { get; init; }

    /// <summary>
    /// Tenant-specific claim requirements (optional).
    /// </summary>
    public Dictionary<string, object>? DefaultClaims { get; init; }

    /// <summary>
    /// Maximum token lifetime in seconds (optional, defaults to service-level setting).
    /// </summary>
    public int? MaxTokenLifetimeSeconds { get; init; }

    /// <summary>
    /// Whether this tenant is currently active.
    /// </summary>
    public bool IsActive { get; init; } = true;
}
