using HeroSdJwt.Exceptions;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Verification;

/// <summary>
/// Provides consistent throwing and result-based entry points for existing verifier interfaces.
/// </summary>
/// <remarks>
/// These methods retain the configured verifier, its policies and dependencies. Verification is
/// performed once; no new verifier is constructed. Try methods return failed results for
/// <see cref="SdJwtException"/> only. Argument errors, cancellation and unexpected implementation
/// exceptions still propagate. Existing VerifyPresentation methods remain available unchanged.
/// </remarks>
public static class SdJwtVerificationExtensions
{
    /// <summary>Verifies a presentation with a direct key, throwing on verification failure.</summary>
    /// <param name="verifier">The configured verifier.</param>
    /// <param name="presentation">The combined SD-JWT presentation.</param>
    /// <param name="verificationKey">The public key or shared secret.</param>
    /// <param name="expectedHashAlgorithm">An additional disclosure hash constraint, or null to use the configured policy.</param>
    /// <returns>A valid verification result.</returns>
    /// <exception cref="SdJwtException">Verification failed.</exception>
    /// <exception cref="ArgumentNullException">A required argument is null.</exception>
    /// <exception cref="OperationCanceledException">A verification dependency canceled its operation.</exception>
    public static VerificationResult Verify(
        this ISdJwtVerifier verifier,
        string presentation,
        byte[] verificationKey,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(verificationKey);
        return RequireValid(verifier.VerifyPresentation(presentation, verificationKey, expectedHashAlgorithm));
    }

    /// <summary>Verifies a presentation with key resolution, throwing on verification failure.</summary>
    /// <param name="verifier">The configured verifier.</param>
    /// <param name="presentation">The combined SD-JWT presentation.</param>
    /// <param name="keyResolver">The existing synchronous key resolver, or null when only a fallback is used.</param>
    /// <param name="fallbackKey">The key used only when the JWT has no key identifier.</param>
    /// <param name="expectedHashAlgorithm">An additional disclosure hash constraint, or null to use the configured policy.</param>
    /// <returns>A valid verification result.</returns>
    /// <exception cref="SdJwtException">Verification failed.</exception>
    /// <exception cref="ArgumentNullException">The verifier or presentation is null.</exception>
    /// <exception cref="OperationCanceledException">A verification dependency canceled its operation.</exception>
    public static VerificationResult Verify(
        this ISdJwtVerifier verifier,
        string presentation,
        KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(presentation);
        return RequireValid(verifier.VerifyPresentation(presentation, keyResolver, fallbackKey, expectedHashAlgorithm));
    }

    /// <summary>Verifies with a direct key, returning a failed result for expected verification errors.</summary>
    /// <param name="verifier">The configured verifier.</param>
    /// <param name="presentation">The combined SD-JWT presentation.</param>
    /// <param name="verificationKey">The public key or shared secret.</param>
    /// <param name="expectedHashAlgorithm">An additional disclosure hash constraint, or null to use the configured policy.</param>
    /// <returns>A result whose IsValid property distinguishes success from verification failure.</returns>
    /// <exception cref="ArgumentNullException">A required argument is null.</exception>
    /// <exception cref="OperationCanceledException">A verification dependency canceled its operation.</exception>
    public static VerificationResult TryVerify(
        this ISdJwtVerifier verifier,
        string presentation,
        byte[] verificationKey,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(verificationKey);
        try
        {
            return verifier.VerifyPresentation(presentation, verificationKey, expectedHashAlgorithm);
        }
        catch (SdJwtException error)
        {
            return Failure(error);
        }
    }

    /// <summary>Verifies with key resolution, returning a failed result for expected verification errors.</summary>
    /// <param name="verifier">The configured verifier.</param>
    /// <param name="presentation">The combined SD-JWT presentation.</param>
    /// <param name="keyResolver">The existing synchronous key resolver, or null when only a fallback is used.</param>
    /// <param name="fallbackKey">The key used only when the JWT has no key identifier.</param>
    /// <param name="expectedHashAlgorithm">An additional disclosure hash constraint, or null to use the configured policy.</param>
    /// <returns>A result whose IsValid property distinguishes success from verification failure.</returns>
    /// <exception cref="ArgumentNullException">The verifier or presentation is null.</exception>
    /// <exception cref="OperationCanceledException">A verification dependency canceled its operation.</exception>
    public static VerificationResult TryVerify(
        this ISdJwtVerifier verifier,
        string presentation,
        KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(presentation);
        try
        {
            return verifier.VerifyPresentation(presentation, keyResolver, fallbackKey, expectedHashAlgorithm);
        }
        catch (SdJwtException error)
        {
            return Failure(error);
        }
    }

    /// <summary>Asynchronously verifies with a direct key, throwing on verification failure.</summary>
    /// <param name="verifier">The configured asynchronous verifier.</param>
    /// <param name="presentation">The combined SD-JWT presentation.</param>
    /// <param name="verificationKey">The public key or shared secret.</param>
    /// <param name="expectedHashAlgorithm">An additional disclosure hash constraint, or null to use the configured policy.</param>
    /// <param name="cancellationToken">The caller's cancellation token, forwarded to the verifier.</param>
    /// <returns>A task producing a valid verification result.</returns>
    /// <exception cref="SdJwtException">Verification failed.</exception>
    /// <exception cref="ArgumentNullException">A required argument is null; checked synchronously.</exception>
    /// <exception cref="OperationCanceledException">The caller or a verification dependency canceled the operation.</exception>
    public static Task<VerificationResult> VerifyAsync(
        this ISdJwtVerifierAsync verifier,
        string presentation,
        byte[] verificationKey,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(verificationKey);
        return VerifyCoreAsync(verifier, presentation, verificationKey, null,
            useResolver: false, throwOnFailure: true, expectedHashAlgorithm, cancellationToken);
    }

    /// <summary>Asynchronously verifies with key resolution, throwing on verification failure.</summary>
    /// <param name="verifier">The configured asynchronous verifier.</param>
    /// <param name="presentation">The combined SD-JWT presentation.</param>
    /// <param name="keyResolver">The existing synchronous key resolver, or null when only a fallback is used.</param>
    /// <param name="fallbackKey">The key used only when the JWT has no key identifier.</param>
    /// <param name="expectedHashAlgorithm">An additional disclosure hash constraint, or null to use the configured policy.</param>
    /// <param name="cancellationToken">The caller's cancellation token, forwarded to the verifier.</param>
    /// <returns>A task producing a valid verification result.</returns>
    /// <exception cref="SdJwtException">Verification failed.</exception>
    /// <exception cref="ArgumentNullException">The verifier or presentation is null; checked synchronously.</exception>
    /// <exception cref="OperationCanceledException">The caller or a verification dependency canceled the operation.</exception>
    public static Task<VerificationResult> VerifyAsync(
        this ISdJwtVerifierAsync verifier,
        string presentation,
        KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(presentation);
        return VerifyCoreAsync(verifier, presentation, fallbackKey, keyResolver,
            useResolver: true, throwOnFailure: true, expectedHashAlgorithm, cancellationToken);
    }

    /// <summary>Asynchronously verifies with a direct key, returning a failed result for expected verification errors.</summary>
    /// <param name="verifier">The configured asynchronous verifier.</param>
    /// <param name="presentation">The combined SD-JWT presentation.</param>
    /// <param name="verificationKey">The public key or shared secret.</param>
    /// <param name="expectedHashAlgorithm">An additional disclosure hash constraint, or null to use the configured policy.</param>
    /// <param name="cancellationToken">The caller's cancellation token, forwarded to the verifier.</param>
    /// <returns>A task producing a result whose IsValid property distinguishes success from verification failure.</returns>
    /// <exception cref="ArgumentNullException">A required argument is null; checked synchronously.</exception>
    /// <exception cref="OperationCanceledException">The caller or a verification dependency canceled the operation.</exception>
    public static Task<VerificationResult> TryVerifyAsync(
        this ISdJwtVerifierAsync verifier,
        string presentation,
        byte[] verificationKey,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(verificationKey);
        return VerifyCoreAsync(verifier, presentation, verificationKey, null,
            useResolver: false, throwOnFailure: false, expectedHashAlgorithm, cancellationToken);
    }

    /// <summary>Asynchronously verifies with key resolution, returning a failed result for expected verification errors.</summary>
    /// <param name="verifier">The configured asynchronous verifier.</param>
    /// <param name="presentation">The combined SD-JWT presentation.</param>
    /// <param name="keyResolver">The existing synchronous key resolver, or null when only a fallback is used.</param>
    /// <param name="fallbackKey">The key used only when the JWT has no key identifier.</param>
    /// <param name="expectedHashAlgorithm">An additional disclosure hash constraint, or null to use the configured policy.</param>
    /// <param name="cancellationToken">The caller's cancellation token, forwarded to the verifier.</param>
    /// <returns>A task producing a result whose IsValid property distinguishes success from verification failure.</returns>
    /// <exception cref="ArgumentNullException">The verifier or presentation is null; checked synchronously.</exception>
    /// <exception cref="OperationCanceledException">The caller or a verification dependency canceled the operation.</exception>
    public static Task<VerificationResult> TryVerifyAsync(
        this ISdJwtVerifierAsync verifier,
        string presentation,
        KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(presentation);
        return VerifyCoreAsync(verifier, presentation, fallbackKey, keyResolver,
            useResolver: true, throwOnFailure: false, expectedHashAlgorithm, cancellationToken);
    }

    private static async Task<VerificationResult> VerifyCoreAsync(
        ISdJwtVerifierAsync verifier,
        string presentation,
        byte[]? key,
        KeyResolver? keyResolver,
        bool useResolver,
        bool throwOnFailure,
        HashAlgorithm? expectedHashAlgorithm,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        VerificationResult result;
        try
        {
            // Do not invoke the legacy Try path: it can convert cancellation into InvalidInput.
            result = useResolver
                ? await verifier.VerifyPresentationAsync(presentation, keyResolver, key,
                    expectedHashAlgorithm, cancellationToken).ConfigureAwait(false)
                : await verifier.VerifyPresentationAsync(presentation, key!,
                    expectedHashAlgorithm, cancellationToken).ConfigureAwait(false);
        }
        catch (SdJwtException error)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (throwOnFailure)
            {
                throw;
            }

            return Failure(error);
        }

        // Custom implementations may ignore cancellation while awaiting their dependencies.
        cancellationToken.ThrowIfCancellationRequested();
        return throwOnFailure ? RequireValid(result) : result;
    }

    private static VerificationResult RequireValid(VerificationResult result)
    {
        if (!result.IsValid)
        {
            throw new SdJwtException("SD-JWT verification failed", result.Errors[0]);
        }

        return result;
    }

    private static VerificationResult Failure(SdJwtException error)
    {
        return new VerificationResult(error.ErrorCode, "SD-JWT verification failed");
    }
}
