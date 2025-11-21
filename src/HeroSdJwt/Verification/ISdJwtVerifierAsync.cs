using HeroSdJwt.Models;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Verification;

/// <summary>
/// Asynchronous SD-JWT presentation verification contract.
/// </summary>
public interface ISdJwtVerifierAsync
{
    /// <summary>
    /// Verifies an SD-JWT presentation using a direct verification key.
    /// Throws <see cref="Exceptions.SdJwtException"/> on failure.
    /// </summary>
    /// <param name="presentation">Presentation string in JWT~disclosure... format.</param>
    /// <param name="publicKey">Verification key.</param>
    /// <param name="expectedHashAlgorithm">Optional expected disclosure hash algorithm.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<VerificationResult> VerifyPresentationAsync(
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Attempts to verify an SD-JWT presentation using a direct key without throwing.
    /// </summary>
    Task<VerificationResult> TryVerifyPresentationAsync(
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies an SD-JWT presentation using key resolution (supports key rotation).
    /// Throws <see cref="Exceptions.SdJwtException"/> on failure.
    /// </summary>
    /// <param name="presentation">Presentation string in JWT~disclosure... format.</param>
    /// <param name="keyResolver">Resolver for 'kid' header.</param>
    /// <param name="fallbackKey">Optional fallback when no kid is present.</param>
    /// <param name="expectedHashAlgorithm">Optional expected disclosure hash algorithm.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<VerificationResult> VerifyPresentationAsync(
        string presentation,
        Primitives.KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Attempts to verify an SD-JWT presentation using key resolution without throwing.
    /// </summary>
    Task<VerificationResult> TryVerifyPresentationAsync(
        string presentation,
        Primitives.KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default);
}
