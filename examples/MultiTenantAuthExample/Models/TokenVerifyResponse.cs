using System.Text.Json;

namespace MultiTenantAuthExample.Models;

/// <summary>
/// Response model for token verification.
/// </summary>
public class TokenVerifyResponse
{
    /// <summary>
    /// Whether the verification was successful.
    /// </summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// Tenant ID extracted from the token.
    /// </summary>
    public string? TenantId { get; init; }

    /// <summary>
    /// Key ID used to sign the token.
    /// </summary>
    public string? KeyId { get; init; }

    /// <summary>
    /// Disclosed claims from the presentation.
    /// </summary>
    public IReadOnlyDictionary<string, JsonElement>? DisclosedClaims { get; init; }

    /// <summary>
    /// Validation errors (if any).
    /// </summary>
    public string[]? Errors { get; init; }
}
