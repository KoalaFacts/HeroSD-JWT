namespace HeroSdJwt.Verification.Revocation;

/// <summary>
/// Defines the storage abstraction for JWT token revocation.
/// Supports three revocation mechanisms: JTI-based (individual tokens),
/// Key ID-based (all tokens from a signing key), and User ID-based
/// (all tokens for a user).
/// </summary>
/// <remarks>
/// <para>
/// Implementations MUST be thread-safe for concurrent operations.
/// All async methods accept a CancellationToken for graceful cancellation.
/// </para>
/// <para>
/// **Default Implementation**: InMemoryRevocationStore (in-memory, single-process)
/// </para>
/// <para>
/// **Custom Implementations**: Users can provide distributed implementations
/// using Redis, SQL databases, or other persistent stores for multi-instance scenarios.
/// </para>
/// </remarks>
public interface IRevocationStore
{
    // ═══════════════════════════════════════════════════════════════════════
    // JTI (JWT ID) Revocation - Individual Token Blacklisting
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Adds a JTI (JWT ID) to the revocation list to invalidate a specific token.
    /// </summary>
    /// <param name="jti">
    /// The unique JWT ID from the 'jti' claim. Must not be null or empty.
    /// </param>
    /// <param name="expiresAt">
    /// The token's expiration time. Used for automatic cleanup. JTI entries
    /// are automatically removed after this time to prevent unbounded growth.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancellation token to abort the operation.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="jti"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="jti"/> is empty or whitespace.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Thrown if cancellation is requested via <paramref name="cancellationToken"/>.
    /// </exception>
    /// <remarks>
    /// This operation SHOULD be idempotent - revoking the same JTI multiple times
    /// is safe and has no additional effect.
    /// </remarks>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RevokeJtiAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks whether a JTI (JWT ID) has been revoked.
    /// </summary>
    /// <param name="jti">
    /// The unique JWT ID from the 'jti' claim to check.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancellation token to abort the operation.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="jti"/> is null.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Thrown if cancellation is requested.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This method is called during every token verification when revocation is enabled.
    /// Implementations MUST be optimized for high-frequency reads (target: 10,000 ops/sec).
    /// </para>
    /// <para>
    /// If the JTI is not found in the revocation list, returns false (not revoked).
    /// </para>
    /// </remarks>
    /// <returns>
    /// A task that resolves to true if the JTI is revoked, false otherwise.
    /// </returns>
    Task<bool> IsJtiRevokedAsync(string jti, CancellationToken cancellationToken = default);

    // ═══════════════════════════════════════════════════════════════════════
    // Key ID Revocation - Bulk Revocation by Signing Key
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Revokes a signing key ID to invalidate all tokens signed with that key.
    /// </summary>
    /// <param name="keyId">
    /// The key identifier from the 'kid' JWT header claim. Must not be null or empty.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancellation token to abort the operation.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="keyId"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="keyId"/> is empty, whitespace, exceeds 256 characters,
    /// or contains non-printable characters.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Thrown if cancellation is requested.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Use this method when a signing key is compromised to immediately invalidate
    /// all tokens signed with that key, without tracking individual JTIs.
    /// </para>
    /// <para>
    /// This operation SHOULD be idempotent - revoking the same key ID multiple times
    /// is safe and has no additional effect.
    /// </para>
    /// <para>
    /// Tokens without a 'kid' header claim are NOT affected by key revocation.
    /// </para>
    /// </remarks>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RevokeKeyAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks whether a signing key ID has been revoked.
    /// </summary>
    /// <param name="keyId">
    /// The key identifier from the 'kid' JWT header claim to check.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancellation token to abort the operation.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="keyId"/> is null.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Thrown if cancellation is requested.
    /// </exception>
    /// <remarks>
    /// This method is called during token verification for tokens that include a 'kid' header.
    /// If the key ID is not found in the revocation list, returns false (not revoked).
    /// </remarks>
    /// <returns>
    /// A task that resolves to true if the key ID is revoked, false otherwise.
    /// </returns>
    Task<bool> IsKeyRevokedAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a key ID from the revocation list to allow tokens signed with that key again.
    /// </summary>
    /// <param name="keyId">
    /// The key identifier to un-revoke.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancellation token to abort the operation.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="keyId"/> is null.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Thrown if cancellation is requested.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Use this method when a key revocation was triggered in error, or when a key
    /// rotation is complete and the old key is confirmed safe.
    /// </para>
    /// <para>
    /// This operation SHOULD be idempotent - unrevoking a key ID that was never
    /// revoked is safe and has no effect.
    /// </para>
    /// </remarks>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task UnrevokeKeyAsync(string keyId, CancellationToken cancellationToken = default);

    // ═══════════════════════════════════════════════════════════════════════
    // User ID Revocation - Emergency Account Lockdown
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Revokes all tokens for a specific user to handle logout or security incidents.
    /// </summary>
    /// <param name="userId">
    /// The user identifier from the 'sub' claim (or custom user claim). Must not be null or empty.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancellation token to abort the operation.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="userId"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="userId"/> is empty or whitespace.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Thrown if cancellation is requested.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Use this method for:
    /// - User-initiated "logout everywhere" functionality
    /// - Emergency account lockdown when suspicious activity is detected
    /// - Forced re-authentication after password change
    /// </para>
    /// <para>
    /// This operation SHOULD be idempotent - revoking the same user ID multiple times
    /// is safe and has no additional effect.
    /// </para>
    /// <para>
    /// Tokens issued AFTER this revocation timestamp SHOULD still be valid
    /// (check token 'iat' claim if implementing time-based filtering).
    /// </para>
    /// </remarks>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RevokeUserAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks whether all tokens for a specific user have been revoked.
    /// </summary>
    /// <param name="userId">
    /// The user identifier from the 'sub' claim to check.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancellation token to abort the operation.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="userId"/> is null.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Thrown if cancellation is requested.
    /// </exception>
    /// <remarks>
    /// This method is called during token verification for all tokens.
    /// If the user ID is not found in the revocation list, returns false (not revoked).
    /// </remarks>
    /// <returns>
    /// A task that resolves to true if the user's tokens are revoked, false otherwise.
    /// </returns>
    Task<bool> IsUserRevokedAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a user ID from the revocation list to allow new token issuance.
    /// </summary>
    /// <param name="userId">
    /// The user identifier to un-revoke.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancellation token to abort the operation.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="userId"/> is null.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Thrown if cancellation is requested.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Use this method when:
    /// - Security incident is resolved and user can log in again
    /// - User completed re-authentication after password change
    /// - Revocation was triggered in error
    /// </para>
    /// <para>
    /// This operation SHOULD be idempotent - unrevoking a user ID that was never
    /// revoked is safe and has no effect.
    /// </para>
    /// <para>
    /// Old tokens issued before the revocation SHOULD still be invalid even after
    /// unrevoking (implementation-dependent - may require checking 'iat' claim).
    /// </para>
    /// </remarks>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task UnrevokeUserAsync(string userId, CancellationToken cancellationToken = default);

    // ═══════════════════════════════════════════════════════════════════════
    // Maintenance Operations
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Removes expired JTI entries from the revocation list to prevent unbounded growth.
    /// </summary>
    /// <param name="cancellationToken">
    /// Cancellation token to abort the operation.
    /// </param>
    /// <exception cref="OperationCanceledException">
    /// Thrown if cancellation is requested.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This method is called automatically by a background timer (default: every 5 minutes).
    /// </para>
    /// <para>
    /// Only JTI entries are cleaned up (they have expiration times). Key ID and User ID
    /// revocations persist until manually removed via UnrevokeKeyAsync/UnrevokeUserAsync.
    /// </para>
    /// <para>
    /// Implementations SHOULD remove all JTI entries where ExpiresAt ≤ current time.
    /// </para>
    /// <para>
    /// **Success Criteria**: 100% of expired entries removed within 1 hour (SC-003).
    /// With a 5-minute timer interval, this is easily achieved.
    /// </para>
    /// </remarks>
    /// <returns>A task representing the asynchronous cleanup operation.</returns>
    Task CleanupExpiredEntriesAsync(CancellationToken cancellationToken = default);
}
