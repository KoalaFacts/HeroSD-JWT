namespace MultiTenantAuthExample.Models;

/// <summary>
/// Request model for issuing SD-JWT tokens for a specific tenant.
/// </summary>
public class TokenIssueRequest
{
    /// <summary>
    /// Tenant identifier for which to issue the token.
    /// </summary>
    public required string TenantId { get; init; }

    /// <summary>
    /// Subject identifier (user ID, service ID, etc.).
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Claims to include in the token.
    /// </summary>
    public required Dictionary<string, object> Claims { get; init; }

    /// <summary>
    /// Which claims should be selectively disclosable.
    /// </summary>
    public string[]? SelectivelyDisclosableClaims { get; init; }

    /// <summary>
    /// Token lifetime in seconds (optional, defaults to tenant/service configuration).
    /// </summary>
    public int? TokenLifetimeSeconds { get; init; }
}
