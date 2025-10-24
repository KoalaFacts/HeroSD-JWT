using HeroSdJwt.Models;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Verification;

/// <summary>
/// Interface for SD-JWT presentation verification.
/// Allows for dependency injection and testing with mock implementations.
/// </summary>
public interface ISdJwtVerifier
{
    /// <summary>
    /// Verifies an SD-JWT presentation using a direct verification key.
    /// Throws <see cref="Exceptions.SdJwtException"/> if verification fails.
    /// </summary>
    /// <param name="presentation">SD-JWT presentation string in format: jwt~disclosure1~disclosure2~...~</param>
    /// <param name="publicKey">Verification key (format depends on algorithm in JWT header).</param>
    /// <param name="expectedHashAlgorithm">Expected hash algorithm for disclosures (optional, defaults to SHA-256).</param>
    /// <returns>Verification result with disclosed claims.</returns>
    /// <exception cref="Exceptions.SdJwtException">Thrown when verification fails.</exception>
    VerificationResult VerifyPresentation(
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm = null);

    /// <summary>
    /// Attempts to verify an SD-JWT presentation using a direct verification key.
    /// Returns result with IsValid=false instead of throwing on verification failure.
    /// </summary>
    /// <param name="presentation">SD-JWT presentation string.</param>
    /// <param name="publicKey">Verification key.</param>
    /// <param name="expectedHashAlgorithm">Expected hash algorithm for disclosures (optional).</param>
    /// <returns>Verification result with IsValid indicating success/failure.</returns>
    VerificationResult TryVerifyPresentation(
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm = null);

    /// <summary>
    /// Verifies an SD-JWT presentation using a key resolver for JWT key rotation support.
    /// Resolves verification key via 'kid' header parameter if present, otherwise uses fallback key.
    /// Throws <see cref="Exceptions.SdJwtException"/> if verification fails.
    /// </summary>
    /// <param name="presentation">SD-JWT presentation string.</param>
    /// <param name="keyResolver">Delegate that resolves key IDs to verification keys (called only if JWT has 'kid' header).</param>
    /// <param name="fallbackKey">Fallback verification key used when JWT has no 'kid' header (optional).</param>
    /// <param name="expectedHashAlgorithm">Expected hash algorithm for disclosures (optional).</param>
    /// <returns>Verification result with disclosed claims.</returns>
    /// <exception cref="Exceptions.SdJwtException">Thrown when verification fails.</exception>
    VerificationResult VerifyPresentation(
        string presentation,
        Primitives.KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null);

    /// <summary>
    /// Attempts to verify an SD-JWT presentation using a key resolver.
    /// Returns result with IsValid=false instead of throwing on verification failure.
    /// </summary>
    /// <param name="presentation">SD-JWT presentation string.</param>
    /// <param name="keyResolver">Delegate that resolves key IDs to verification keys.</param>
    /// <param name="fallbackKey">Fallback verification key (optional).</param>
    /// <param name="expectedHashAlgorithm">Expected hash algorithm for disclosures (optional).</param>
    /// <returns>Verification result with IsValid indicating success/failure.</returns>
    VerificationResult TryVerifyPresentation(
        string presentation,
        Primitives.KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null);
}
