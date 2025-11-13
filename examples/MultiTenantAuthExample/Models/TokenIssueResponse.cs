namespace MultiTenantAuthExample.Models;

/// <summary>
/// Response model for token issuance containing the SD-JWT.
/// </summary>
public class TokenIssueResponse
{
    /// <summary>
    /// The issued SD-JWT in combined format.
    /// </summary>
    public required string SdJwt { get; init; }

    /// <summary>
    /// Tenant ID for which the token was issued.
    /// </summary>
    public required string TenantId { get; init; }

    /// <summary>
    /// Key ID used to sign this token.
    /// </summary>
    public required string KeyId { get; init; }

    /// <summary>
    /// Token expiration timestamp (Unix epoch seconds).
    /// </summary>
    public required long ExpiresAt { get; init; }

    /// <summary>
    /// Available claims that can be selectively disclosed.
    /// </summary>
    public required string[] SelectivelyDisclosableClaims { get; init; }
}
