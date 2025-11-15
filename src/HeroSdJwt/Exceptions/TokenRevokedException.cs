using HeroSdJwt.Primitives;

namespace HeroSdJwt.Exceptions;

/// <summary>
/// Exception thrown when a token has been explicitly revoked.
/// Provides context about the type of revocation (JTI, Key ID, or User ID).
/// </summary>
public sealed class TokenRevokedException : SdJwtException
{
    /// <summary>
    /// Gets the JTI (JWT ID) of the revoked token, if revocation was by JTI.
    /// </summary>
    public string? Jti { get; }

    /// <summary>
    /// Gets the Key ID of the revoked signing key, if revocation was by Key ID.
    /// </summary>
    public string? KeyId { get; }

    /// <summary>
    /// Gets the User ID whose tokens were revoked, if revocation was by User ID.
    /// </summary>
    public string? UserId { get; }

    /// <summary>
    /// Gets the reason for revocation (JTI, Key ID, or User ID based).
    /// </summary>
    public RevocationReason Reason { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRevokedException"/> class
    /// for JTI-based revocation.
    /// </summary>
    /// <param name="jti">The revoked JTI (JWT ID).</param>
    public TokenRevokedException(string jti)
        : base("Token has been revoked", ErrorCode.TokenRevoked)
    {
        Jti = jti;
        Reason = RevocationReason.JtiRevoked;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRevokedException"/> class
    /// for Key ID-based revocation.
    /// </summary>
    /// <param name="keyId">The revoked key identifier.</param>
    /// <param name="reason">The revocation reason (must be <see cref="RevocationReason.KeyRevoked"/>).</param>
    public TokenRevokedException(string keyId, RevocationReason reason)
        : base("Token's signing key has been revoked", ErrorCode.TokenRevokedByKey)
    {
        if (reason != RevocationReason.KeyRevoked)
            throw new ArgumentException("Reason must be KeyRevoked for key-based revocation", nameof(reason));

        KeyId = keyId;
        Reason = reason;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRevokedException"/> class
    /// for User ID-based revocation.
    /// </summary>
    /// <param name="userId">The revoked user identifier.</param>
    /// <param name="reason">The revocation reason (must be <see cref="RevocationReason.UserRevoked"/>).</param>
    /// <param name="jti">Optional JTI for logging purposes.</param>
    public TokenRevokedException(string userId, RevocationReason reason, string? jti)
        : base("User's tokens have been revoked", ErrorCode.TokenRevokedByUser)
    {
        if (reason != RevocationReason.UserRevoked)
            throw new ArgumentException("Reason must be UserRevoked for user-based revocation", nameof(reason));

        UserId = userId;
        Jti = jti;
        Reason = reason;
    }
}

/// <summary>
/// Specifies the type of revocation that occurred.
/// </summary>
public enum RevocationReason
{
    /// <summary>
    /// Token was revoked by its JTI (JWT ID).
    /// Individual token blacklisting (e.g., user logout).
    /// </summary>
    JtiRevoked,

    /// <summary>
    /// Token was revoked because its signing key ID was revoked.
    /// All tokens signed with the compromised key are invalid.
    /// </summary>
    KeyRevoked,

    /// <summary>
    /// Token was revoked because the user's ID was revoked.
    /// All tokens for the user are invalid (e.g., emergency lockdown).
    /// </summary>
    UserRevoked
}
