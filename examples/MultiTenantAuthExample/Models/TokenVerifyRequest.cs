namespace MultiTenantAuthExample.Models;

/// <summary>
/// Request model for verifying SD-JWT presentations.
/// </summary>
public class TokenVerifyRequest
{
    /// <summary>
    /// The SD-JWT presentation string to verify (format: jwt~disclosure~disclosure~...).
    /// </summary>
    public required string Presentation { get; init; }

    /// <summary>
    /// Optional tenant hint for verification (if not provided, will be extracted from JWT).
    /// </summary>
    public string? TenantId { get; init; }
}
