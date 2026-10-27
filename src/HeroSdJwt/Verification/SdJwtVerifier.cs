using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Verification.ReplayProtection;
using HeroSdJwt.Verification.Revocation;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;
using System.Text.Json;
using Constants = HeroSdJwt.Primitives.Constants;
using ErrorCode = HeroSdJwt.Primitives.ErrorCode;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Verification;

/// <summary>
/// Verifies SD-JWT presentations by validating signatures, digests, and claims.
/// Implements security measures including constant-time comparison, algorithm confusion prevention,
/// and timing attack resistance.
/// Configured hash algorithm policy and per-call hash algorithm constraints must both be satisfied.
/// </summary>
public class SdJwtVerifier : ISdJwtVerifier, ISdJwtVerifierAsync, ISdJwtVerifierFactory
{
    private readonly SdJwtVerificationOptions _options;
    private readonly IEcPublicKeyConverter _ecPublicKeyConverter;
    private readonly ISignatureValidator _signatureValidator;
    private readonly IDigestValidator _digestValidator;
    private readonly IKeyBindingValidator _keyBindingValidator;
    private readonly IClaimValidator _claimValidator;
    private readonly IRevocationStore? _revocationStore;
    private readonly JtiValidator? _jtiValidator;

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtVerifier"/> class with dependencies.
    /// For simple usage: new SdJwtVerifier(new SdJwtVerificationOptions(), new EcPublicKeyConverter(), new SignatureValidator(), new DigestValidator(), new KeyBindingValidator(), new ClaimValidator())
    /// </summary>
    /// <param name="options">Verification options.</param>
    /// <param name="ecPublicKeyConverter">EC public key converter.</param>
    /// <param name="signatureValidator">Signature validator.</param>
    /// <param name="digestValidator">Digest validator.</param>
    /// <param name="keyBindingValidator">Key binding validator.</param>
    /// <param name="claimValidator">Claim validator.</param>
    /// <param name="jtiValidator">Optional JTI validator for replay attack prevention. If null, replay protection is disabled (backward compatibility).</param>
    /// <param name="revocationStore">Optional revocation store for token revocation checking. If null, revocation checks are skipped (backward compatibility).</param>
    public SdJwtVerifier(
        SdJwtVerificationOptions options,
        IEcPublicKeyConverter ecPublicKeyConverter,
        ISignatureValidator signatureValidator,
        IDigestValidator digestValidator,
        IKeyBindingValidator keyBindingValidator,
        IClaimValidator claimValidator,
        JtiValidator? jtiValidator = null,
        IRevocationStore? revocationStore = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signatureValidator);
        ArgumentNullException.ThrowIfNull(digestValidator);
        ArgumentNullException.ThrowIfNull(keyBindingValidator);
        ArgumentNullException.ThrowIfNull(claimValidator);

        options.Validate();
        _options = options;
        _ecPublicKeyConverter = ecPublicKeyConverter;
        _signatureValidator = signatureValidator;
        _digestValidator = digestValidator;
        _keyBindingValidator = keyBindingValidator;
        _claimValidator = claimValidator;
        _jtiValidator = jtiValidator;
        _revocationStore = revocationStore;
    }

    /// <summary>
    /// Creates a verifier for a separate policy while preserving configured validators, replay
    /// protection and revocation dependencies. The source verifier's policy is never changed.
    /// </summary>
    /// <param name="options">The complete verification policy.</param>
    /// <returns>A verifier for the supplied policy.</returns>
    /// <remarks>
    /// Derived verifiers must override this method to explicitly retain their custom behavior.
    /// </remarks>
    public virtual ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (GetType() != typeof(SdJwtVerifier))
        {
            throw new InvalidOperationException(
                "Derived verifiers must override ISdJwtVerifierFactory.CreateVerifier to preserve custom verification behavior.");
        }

        return new SdJwtVerifier(
            options,
            _ecPublicKeyConverter,
            _signatureValidator,
            _digestValidator,
            _keyBindingValidator,
            _claimValidator,
            _jtiValidator,
            _revocationStore);
    }

    /// <summary>
    /// Verifies an SD-JWT presentation.
    /// Throws exceptions on validation failures.
    /// </summary>
    /// <param name="presentation">The combined SD-JWT presentation string (JWT~disclosure1~disclosure2~...~keyBinding).</param>
    /// <param name="publicKey">The public key or shared secret for signature verification.</param>
    /// <param name="expectedHashAlgorithm">Optional expected hash algorithm for disclosure digests.</param>
    /// <returns>Verification result with validation status and disclosed claims.</returns>
    /// <exception cref="ArgumentNullException">Thrown when presentation or publicKey is null.</exception>
    /// <exception cref="AlgorithmConfusionException">Thrown when JWT uses "none" algorithm.</exception>
    /// <exception cref="AlgorithmNotSupportedException">Thrown when JWT uses unsupported algorithm.</exception>
    /// <exception cref="SdJwtException">Thrown when validation fails.</exception>
    public VerificationResult VerifyPresentation(
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(publicKey);

        // Synchronous API is retained for compatibility; it bridges to the async pipeline and blocks.
        var result = VerifyPresentationInternalAsync(
            presentation,
            publicKey,
            expectedHashAlgorithm,
            CancellationToken.None).GetAwaiter().GetResult();

        // Throw exception if verification failed
        // Note: Error details are sanitized to prevent information disclosure
        if (!result.IsValid)
        {
            var primaryError = result.Errors.FirstOrDefault();
            throw new SdJwtException("SD-JWT verification failed", primaryError);
        }

        return result;
    }

    /// <summary>
    /// Attempts to verify an SD-JWT presentation without throwing exceptions.
    /// Returns a result object with validation status and errors.
    /// Follows the standard .NET Try* pattern (similar to TryParse, TryGetValue).
    /// </summary>
    /// <param name="presentation">The combined SD-JWT presentation string.</param>
    /// <param name="publicKey">The public key or shared secret for signature verification.</param>
    /// <param name="expectedHashAlgorithm">Optional expected hash algorithm.</param>
    /// <returns>Verification result with validation status, errors, and disclosed claims.</returns>
    public VerificationResult TryVerifyPresentation(
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(publicKey);

        try
        {
            // Synchronous API is retained for compatibility; it bridges to the async pipeline and blocks.
            return VerifyPresentationInternalAsync(
                presentation,
                publicKey,
                expectedHashAlgorithm,
                CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (TokenRevokedException ex) { return new VerificationResult(ex.ErrorCode, ex.Message); }
        catch (ReplayAttackException ex)
        {
            return new VerificationResult(ErrorCode.ReplayAttack, ex.Message);
        }
        catch (AlgorithmConfusionException ex)
        {
            return new VerificationResult(ErrorCode.AlgorithmConfusion, ex.Message);
        }
        catch (AlgorithmNotSupportedException ex)
        {
            return new VerificationResult(ErrorCode.UnsupportedAlgorithm, ex.Message);
        }
        catch (SdJwtException ex)
        {
            // Preserve the error code from SdJwtException
            return new VerificationResult(ex.ErrorCode, $"Verification failed: {ex.Message}");
        }
        catch (Exception ex)
        {
            return new VerificationResult(ErrorCode.InvalidInput, $"Verification failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Asynchronously verifies an SD-JWT presentation.
    /// Throws exceptions on validation failures.
    /// </summary>
    public Task<VerificationResult> VerifyPresentationAsync(
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(publicKey);

        return VerifyPresentationInternalAsync(
            presentation,
            publicKey,
            expectedHashAlgorithm,
            cancellationToken);
    }

    /// <summary>
    /// Asynchronously attempts to verify an SD-JWT presentation without throwing exceptions.
    /// </summary>
    public async Task<VerificationResult> TryVerifyPresentationAsync(
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(publicKey);

        try
        {
            return await VerifyPresentationInternalAsync(
                presentation,
                publicKey,
                expectedHashAlgorithm,
                cancellationToken).ConfigureAwait(false);
        }
        catch (TokenRevokedException ex) { return new VerificationResult(ex.ErrorCode, ex.Message); }
        catch (ReplayAttackException ex) { return new VerificationResult(ErrorCode.ReplayAttack, ex.Message); }
        catch (AlgorithmConfusionException ex) { return new VerificationResult(ErrorCode.AlgorithmConfusion, ex.Message); }
        catch (AlgorithmNotSupportedException ex) { return new VerificationResult(ErrorCode.UnsupportedAlgorithm, ex.Message); }
        catch (SdJwtException ex) { return new VerificationResult(ex.ErrorCode, $"Verification failed: {ex.Message}"); }
        catch (Exception ex) { return new VerificationResult(ErrorCode.InvalidInput, $"Verification failed: {ex.Message}"); }
    }

    /// <summary>
    /// Verifies an SD-JWT presentation using key resolution.
    /// Throws exceptions on validation failures.
    /// </summary>
    /// <param name="presentation">The combined SD-JWT presentation string (JWT~disclosure1~disclosure2~...~keyBinding).</param>
    /// <param name="keyResolver">Delegate to resolve key IDs to verification keys.</param>
    /// <param name="fallbackKey">Optional fallback key when JWT has no 'kid' parameter (backward compatibility).</param>
    /// <param name="expectedHashAlgorithm">Optional expected hash algorithm for disclosure digests.</param>
    /// <returns>Verification result with validation status and disclosed claims.</returns>
    /// <exception cref="ArgumentNullException">Thrown when presentation is null.</exception>
    /// <exception cref="SdJwtException">Thrown when validation fails.</exception>
    public VerificationResult VerifyPresentation(
        string presentation,
        KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(presentation);

        var result = VerifyPresentationInternalWithResolverAsync(
            presentation,
            keyResolver,
            fallbackKey,
            expectedHashAlgorithm,
            CancellationToken.None).GetAwaiter().GetResult();

        if (!result.IsValid)
        {
            var primaryError = result.Errors.FirstOrDefault();
            throw new SdJwtException("SD-JWT verification failed", primaryError);
        }

        return result;
    }

    /// <summary>
    /// Attempts to verify an SD-JWT presentation using key resolution without throwing exceptions.
    /// Returns a result object with validation status and errors.
    /// Follows the standard .NET Try* pattern (similar to TryParse, TryGetValue).
    /// </summary>
    /// <param name="presentation">The combined SD-JWT presentation string.</param>
    /// <param name="keyResolver">Delegate to resolve key IDs to verification keys.</param>
    /// <param name="fallbackKey">Optional fallback key when JWT has no 'kid' parameter.</param>
    /// <param name="expectedHashAlgorithm">Optional expected hash algorithm.</param>
    /// <returns>Verification result with validation status, errors, and disclosed claims.</returns>
    public VerificationResult TryVerifyPresentation(
        string presentation,
        KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(presentation);

        try
        {
            // Synchronous API is retained for compatibility; it bridges to the async pipeline and blocks.
            return VerifyPresentationInternalWithResolverAsync(
                presentation,
                keyResolver,
                fallbackKey,
                expectedHashAlgorithm,
                CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (TokenRevokedException ex) { return new VerificationResult(ex.ErrorCode, ex.Message); }
        catch (ReplayAttackException ex)
        {
            return new VerificationResult(ErrorCode.ReplayAttack, ex.Message);
        }
        catch (AlgorithmConfusionException ex)
        {
            return new VerificationResult(ErrorCode.AlgorithmConfusion, ex.Message);
        }
        catch (AlgorithmNotSupportedException ex)
        {
            return new VerificationResult(ErrorCode.UnsupportedAlgorithm, ex.Message);
        }
        catch (SdJwtException ex)
        {
            return new VerificationResult(ex.ErrorCode, $"Verification failed: {ex.Message}");
        }
        catch (Exception ex)
        {
            return new VerificationResult(ErrorCode.InvalidInput, $"Verification failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Asynchronously verifies an SD-JWT presentation using key resolution.
    /// </summary>
    public Task<VerificationResult> VerifyPresentationAsync(
        string presentation,
        KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);

        return VerifyPresentationInternalWithResolverAsync(
            presentation,
            keyResolver,
            fallbackKey,
            expectedHashAlgorithm,
            cancellationToken);
    }

    /// <summary>
    /// Asynchronously attempts to verify an SD-JWT presentation using key resolution.
    /// </summary>
    public async Task<VerificationResult> TryVerifyPresentationAsync(
        string presentation,
        KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);

        try
        {
            return await VerifyPresentationInternalWithResolverAsync(
                presentation,
                keyResolver,
                fallbackKey,
                expectedHashAlgorithm,
                cancellationToken).ConfigureAwait(false);
        }
        catch (TokenRevokedException ex) { return new VerificationResult(ex.ErrorCode, ex.Message); }
        catch (ReplayAttackException ex) { return new VerificationResult(ErrorCode.ReplayAttack, ex.Message); }
        catch (AlgorithmConfusionException ex) { return new VerificationResult(ErrorCode.AlgorithmConfusion, ex.Message); }
        catch (AlgorithmNotSupportedException ex) { return new VerificationResult(ErrorCode.UnsupportedAlgorithm, ex.Message); }
        catch (SdJwtException ex) { return new VerificationResult(ex.ErrorCode, $"Verification failed: {ex.Message}"); }
        catch (Exception ex) { return new VerificationResult(ErrorCode.InvalidInput, $"Verification failed: {ex.Message}"); }
    }

    /// <summary>
    /// Internal verification logic with key resolver support.
    /// </summary>
    private async Task<VerificationResult> VerifyPresentationInternalWithResolverAsync(
        string presentation,
        KeyResolver? keyResolver,
        byte[]? fallbackKey,
        HashAlgorithm? expectedHashAlgorithm,
        CancellationToken cancellationToken)
    {
        var errors = new List<ErrorCode>();
        var errorDetails = new List<string>();

        // Validate presentation size to prevent DoS attacks
        if (presentation.Length > Constants.MAX_JWT_SIZE_BYTES)
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add($"Presentation exceeds maximum allowed size of {Constants.MAX_JWT_SIZE_BYTES} bytes");
            return new VerificationResult(errors, string.Join("; ", errorDetails));
        }

        // Parse presentation into parts: JWT~disclosure1~disclosure2~...~keyBinding
        var parts = SplitPresentationComponents(presentation);
        if (parts is null)
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add($"Presentation exceeds maximum of {Constants.MAX_DISCLOSURES} disclosure slots");
            return new VerificationResult(errors, string.Join("; ", errorDetails));
        }

        if (parts.Length < 2)
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add("Invalid presentation format: expected at least JWT and empty slots");
            return new VerificationResult(errors, string.Join("; ", errorDetails));
        }

        // Reject excess separators before allocating any component strings.
        // RFC 9901: each intermediate component must be an actual Disclosure.
        // A whitespace-only final component is not an absent Key Binding JWT.
        // Reject malformed shapes before key resolution or signature work.
        if (HasMalformedPresentationComponents(parts))
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add("Invalid presentation format: empty Disclosure or whitespace-only component");
            return new VerificationResult(errors, string.Join("; ", errorDetails));
        }

        var jwt = parts[0];

        // Step 1: Extract kid from JWT header and resolve to verification key
        byte[] verificationKey;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Parse JWT header to check for kid
            var jwtParts = CompactJwtSplitter.Split(jwt);
            if (jwtParts is null)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("Invalid JWT format");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            var headerJson = Base64UrlEncoder.DecodeString(jwtParts[0]);
            var header = JsonDocument.Parse(headerJson).RootElement;

            if (JoseHeaderGuard.HasInvalidOrUnsupportedParameters(header))
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("JWT protected header has invalid or unsupported parameters");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Check if kid is present
            if (header.TryGetProperty("kid", out var kidElement) && kidElement.ValueKind == JsonValueKind.String)
            {
                var keyId = kidElement.GetString();

                KeyIdGuard.EnsureValid(keyId);
                var resolvedKeyId = keyId!;

                // Use resolver
                if (keyResolver == null)
                {
                    throw new SdJwtException(
                        "JWT contains 'kid' parameter but no key resolver was provided",
                        ErrorCode.KeyResolverMissing);
                }

                try
                {
                    verificationKey = keyResolver(resolvedKeyId)
                        ?? throw new SdJwtException(
                            $"Key resolver could not find key for kid '{resolvedKeyId}'",
                            ErrorCode.KeyIdNotFound);
                }
                catch (SdJwtException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    throw new SdJwtException(
                        $"Key resolver threw an exception while resolving kid '{resolvedKeyId}': {ex.Message}",
                        ErrorCode.KeyResolverFailed,
                        ex);
                }
            }
            else
            {
                // No kid - use fallback
                if (fallbackKey == null)
                {
                    throw new SdJwtException(
                        "JWT has no 'kid' parameter and no fallback key was provided",
                        ErrorCode.KeyResolverMissing);
                }

                verificationKey = fallbackKey;
            }
        }
        catch (SdJwtException)
        {
            throw;
        }
        catch (Exception ex)
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add($"Failed to parse JWT header: {ex.Message}");
            return new VerificationResult(errors, string.Join("; ", errorDetails));
        }

        // Step 2: Delegate to existing internal method with resolved key
        // This handles signature verification, temporal claims, disclosures, key binding, etc.
        return await VerifyPresentationInternalAsync(
            presentation,
            verificationKey,
            expectedHashAlgorithm,
            cancellationToken).ConfigureAwait(false);
    }

    private static bool HasMalformedPresentationComponents(string[] parts)
    {
        // The final empty string denotes an SD-JWT without Key Binding.
        // Extra empty slots or whitespace-only strings are not Disclosures.
        for (int i = 1; i < parts.Length - 1; i++)
        {
            if (string.IsNullOrWhiteSpace(parts[i]))
            {
                return true;
            }
        }

        return parts[^1].Length > 0 && string.IsNullOrWhiteSpace(parts[^1]);
    }

    /// <summary>
    /// Internal verification logic shared by both throwing and non-throwing methods.
    /// </summary>
    private async Task<VerificationResult> VerifyPresentationInternalAsync(
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm,
        CancellationToken cancellationToken)
    {
        var errors = new List<ErrorCode>();
        var errorDetails = new List<string>();
        var expectedAudiences = _options.GetExpectedAudiences();

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Validate presentation size to prevent DoS attacks
            if (presentation.Length > Constants.MAX_JWT_SIZE_BYTES)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add($"Presentation exceeds maximum allowed size of {Constants.MAX_JWT_SIZE_BYTES} bytes");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Parse presentation into parts: JWT~disclosure1~disclosure2~...~keyBinding
            var parts = SplitPresentationComponents(presentation);
            if (parts is null)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add($"Presentation exceeds maximum of {Constants.MAX_DISCLOSURES} disclosure slots");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            if (parts.Length < 2)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("Invalid presentation format: expected at least JWT and empty slots");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Reject excess separators before allocating any component strings.
            // RFC 9901: each intermediate component must be an actual Disclosure.
            // A whitespace-only final component is not an absent Key Binding JWT.
            // Reject malformed shapes before key resolution or signature work.
            if (HasMalformedPresentationComponents(parts))
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("Invalid presentation format: empty Disclosure or whitespace-only component");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            var jwt = parts[0];

            // Validate JWT size
            if (jwt.Length > Constants.MAX_JWT_SIZE_BYTES / 2)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("JWT component exceeds reasonable size limit");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }
            var disclosures = new List<string>();
            HashSet<string>? seenDisclosures = null;
            var keyBindingJwt = parts.Length > 1 ? parts[^1] : null;

            // Extract disclosures (all parts between JWT and key binding, excluding empty strings)
            // Limit to prevent DoS attacks via excessive disclosures
            for (int i = 1; i < parts.Length - 1; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!string.IsNullOrWhiteSpace(parts[i]))
                {
                    if (disclosures.Count >= Constants.MAX_DISCLOSURES)
                    {
                        errors.Add(ErrorCode.InvalidInput);
                        errorDetails.Add($"Too many disclosures: exceeds maximum of {Constants.MAX_DISCLOSURES}");
                        return new VerificationResult(errors, string.Join("; ", errorDetails));
                    }

                    // RFC 9901 Section 4 prohibits sending the same Disclosure twice.
                    // Avoid an additional allocation for zero or one Disclosure.
                    if (disclosures.Count > 0)
                    {
                        seenDisclosures ??= new HashSet<string>([disclosures[0]], StringComparer.Ordinal);
                        if (!seenDisclosures.Add(parts[i]))
                        {
                            errors.Add(ErrorCode.InvalidInput);
                            errorDetails.Add("The same Disclosure must not appear more than once");
                            return new VerificationResult(errors, string.Join("; ", errorDetails));
                        }
                    }

                    disclosures.Add(parts[i]);
                }
            }

            // Parse JWT structure up front
            var jwtParts = CompactJwtSplitter.Split(jwt);
            if (jwtParts is null)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("Invalid JWT format");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Parse JWT header for algorithm and kid extraction
            JsonElement header;
            try
            {
                var headerJson = Base64UrlEncoder.DecodeString(jwtParts[0]);
                header = JsonDocument.Parse(headerJson).RootElement;
            }
            catch (Exception ex)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add($"Failed to parse JWT header: {ex.Message}");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            if (JoseHeaderGuard.HasInvalidOrUnsupportedParameters(header))
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("JWT protected header has invalid or unsupported parameters");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Validate algorithm vs expected key type before signature verification to prevent confusion attacks
            if (!header.TryGetProperty("alg", out var algElement) || algElement.ValueKind != JsonValueKind.String)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("JWT header missing required 'alg' claim");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            var alg = algElement.GetString() ?? string.Empty;
            try
            {
                ValidateAlgorithmAgainstKeyType(alg, _options.ExpectedKeyType);
            }
            catch (SdJwtException ex)
            {
                errors.Add(ex.ErrorCode);
                errorDetails.Add(ex.Message);
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Step 1: Verify JWT signature
            bool signatureValid = false;
            try
            {
                signatureValid = _signatureValidator.VerifyJwtSignature(jwt, publicKey);
            }
            catch (AlgorithmConfusionException)
            {
                throw; // Re-throw algorithm confusion exceptions
            }
            catch (AlgorithmNotSupportedException)
            {
                throw; // Re-throw unsupported algorithm exceptions
            }
            catch (Exception ex)
            {
                errors.Add(ErrorCode.InvalidSignature);
                errorDetails.Add($"Signature validation failed: {ex.Message}");
            }

            if (!signatureValid)
            {
                if (errors.Count == 0)
                {
                    errors.Add(ErrorCode.InvalidSignature);
                    errorDetails.Add("JWT signature is invalid");
                }

                // Do not process untrusted claims, Disclosures, or revocation state when
                // the issuer's JWS signature has not been authenticated.
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Step 2: Parse JWT payload
            JsonElement payload;
            try
            {
                var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
                payload = JsonDocument.Parse(payloadJson).RootElement;
            }
            catch (Exception ex)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add($"Failed to parse JWT payload: {ex.Message}");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // A JWS payload for SD-JWT must be a JSON claims object. Do not let
            // malformed, correctly signed payloads escape as InvalidOperationException.
            if (payload.ValueKind != JsonValueKind.Object)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("JWT payload must be a JSON object");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // RFC 7519 requires unique top-level claim names. The JSON DOM's
            // last-wins lookup is ambiguous even when the JWS signature is valid.
            if (JsonObjectMemberGuard.HasInvalidOrDuplicateNames(payload))
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("JWT payload contains duplicate or invalid claim names");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            var payloadAudiences = ExtractAudiences(payload);

            // Step 3: Validate temporal claims (exp, nbf, iat)
            bool claimsValid = _claimValidator.ValidateTemporalClaims(payload, _options);
            if (!claimsValid)
            {
                errors.Add(ErrorCode.TokenExpired);
                errorDetails.Add("Temporal claims validation failed");
            }

            // Validate issuer if configured
            if (!_claimValidator.ValidateIssuer(payload, _options.ExpectedIssuer))
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("Issuer validation failed");
            }

            // Validate audience if configured
            if (!_claimValidator.ValidateAudience(payload, expectedAudiences))
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("Audience validation failed");
            }

            // Step 4: Validate disclosure digests
            HashAlgorithm algorithm;
            try
            {
                algorithm = GetHashAlgorithm(payload, expectedHashAlgorithm);
            }
            catch (SdJwtException ex) when (ex.ErrorCode == ErrorCode.AlgorithmConfusion)
            {
                errors.Add(ErrorCode.HashAlgorithmMismatch);
                errorDetails.Add(ex.Message);
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Collect all _sd array digests from both the JWT payload AND disclosure values
            // This supports nested selective disclosure per SD-JWT spec
            var expectedDigests = new List<Digest>();
            var arrayDigests = new List<Digest>();
            var seenDigests = new HashSet<string>(StringComparer.Ordinal);
            var nonArrayDisclosures = new List<string>();
            var arrayDisclosures = new List<string>();
            if (!CollectAllSdDigests(
                payload, expectedDigests, arrayDigests, algorithm, seenDigests, allowTopLevelSdAlg: true))
            {
                errors.Add(ErrorCode.InvalidInput);
                return new VerificationResult(errors, "Invalid or repeated SD-JWT disclosure digest reference");
            }

            // Also collect _sd digests from disclosure values (for nested structures)
            foreach (var disclosure in disclosures)
            {
                nonArrayDisclosures.Add(disclosure);
                try
                {
                    var json = Base64UrlEncoder.DecodeString(disclosure);
                    using var document = JsonDocument.Parse(json);
                    var array = document.RootElement;

                    if (array.ValueKind == JsonValueKind.Array && array.GetArrayLength() >= 2)
                    {
                        // For 3-element disclosures, check if the value contains _sd arrays
                        var valueIndex = array.GetArrayLength() == 3 ? 2 : 1;
                        var value = array[valueIndex];
                        if (array.GetArrayLength() == 2)
                        {
                            nonArrayDisclosures.Remove(disclosure);
                            arrayDisclosures.Add(disclosure);
                        }
                        if (!CollectAllSdDigests(value, expectedDigests, arrayDigests, algorithm, seenDigests))
                        {
                            errors.Add(ErrorCode.InvalidInput);
                            return new VerificationResult(errors, "Invalid or repeated SD-JWT disclosure digest reference");
                        }
                    }
                }
                catch
                {
                    // Skip malformed disclosures
                }
            }

            if (nonArrayDisclosures.Any(disclosure => arrayDigests.Any(digest =>
                _digestValidator.ValidateDigest(disclosure, digest, algorithm))))
            {
                errors.Add(ErrorCode.InvalidInput);
                return new VerificationResult(errors, "Array placeholders require two-element disclosures");
            }

            // A two-element Disclosure is valid only for an array placeholder.
            // A matching object _sd digest cannot turn it into a claim value.
            if (arrayDisclosures.Any(disclosure => expectedDigests.Any(digest =>
                !arrayDigests.Any(arrayDigest => arrayDigest.Value == digest.Value) &&
                _digestValidator.ValidateDigest(disclosure, digest, algorithm))))
            {
                errors.Add(ErrorCode.InvalidInput);
                return new VerificationResult(errors, "Object disclosure digests require three-element disclosures");
            }

            if (disclosures.Count > 0)
            {
                bool digestsValid = _digestValidator.ValidateAllDigests(disclosures, expectedDigests, algorithm);
                if (!digestsValid)
                {
                    errors.Add(ErrorCode.DigestMismatch);
                    errorDetails.Add("Disclosure digest validation failed");
                }
            }

            var keyBindingAudiences = GetMatchingAudiences(expectedAudiences, payloadAudiences);

            // Step 5: Validate key binding if present or required
            if (!string.IsNullOrWhiteSpace(keyBindingJwt))
            {
                // Extract holder's public key from cnf claim
                if (!payload.TryGetProperty("cnf", out var cnfElement) ||
                    cnfElement.ValueKind != JsonValueKind.Object ||
                    !cnfElement.TryGetProperty("jwk", out var jwkElement))
                {
                    errors.Add(ErrorCode.InvalidInput);
                    errorDetails.Add("Key binding JWT present but cnf claim missing from SD-JWT");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }

                byte[] holderPublicKey;
                try
                {
                    // Parse JWK per RFC 7800 - support both legacy base64 format and proper JWK
                    if (jwkElement.ValueKind == JsonValueKind.String)
                    {
                        // Legacy format: base64-encoded raw key (for backward compatibility)
                        var jwkBase64 = jwkElement.GetString();
                        if (string.IsNullOrWhiteSpace(jwkBase64))
                        {
                            errors.Add(ErrorCode.InvalidInput);
                            errorDetails.Add("Invalid cnf claim: jwk is empty");
                            return new VerificationResult(errors, string.Join("; ", errorDetails));
                        }
                        holderPublicKey = Convert.FromBase64String(jwkBase64);
                    }
                    else if (jwkElement.ValueKind == JsonValueKind.Object)
                    {
                        // RFC 7800 format: proper JWK with kty, crv, x, y
                        holderPublicKey = _ecPublicKeyConverter.FromJwk(jwkElement);
                    }
                    else
                    {
                        errors.Add(ErrorCode.InvalidInput);
                        errorDetails.Add("Invalid cnf claim: jwk must be a string or object");
                        return new VerificationResult(errors, string.Join("; ", errorDetails));
                    }

                    // Validate the public key format and curve
                    using var ecdsa = ECDsa.Create();
                    ecdsa.ImportSubjectPublicKeyInfo(holderPublicKey, out _);

                    // Only P-256 (ES256) is supported
                    if (!EcCurveGuard.IsP256(ecdsa))
                    {
                        errors.Add(ErrorCode.UnsupportedAlgorithm);
                        errorDetails.Add("Unsupported elliptic curve: ES256 requires the named NIST P-256 curve.");
                        return new VerificationResult(errors, string.Join("; ", errorDetails));
                    }
                }
                catch (FormatException)
                {
                    errors.Add(ErrorCode.InvalidInput);
                    errorDetails.Add("Invalid cnf claim: jwk encoding error");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }
                catch (CryptographicException)
                {
                    errors.Add(ErrorCode.InvalidInput);
                    errorDetails.Add("Invalid cnf claim: jwk is not a valid ECDSA public key");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }
                catch (PlatformNotSupportedException)
                {
                    // Reject unsupported holder curves on platforms that cannot import them.
                    errors.Add(ErrorCode.UnsupportedAlgorithm);
                    errorDetails.Add("Invalid cnf claim: holder key curve is unsupported on this platform");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }
                catch (ArgumentException ex)
                {
                    errors.Add(ErrorCode.InvalidInput);
                    errorDetails.Add($"Invalid cnf claim JWK: {ex.Message}");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }

                // Compute SD-JWT hash for key binding validation
                // The hash is computed over: JWT~disclosure1~disclosure2~...~
                // (everything before the key binding JWT, including the trailing tilde)
                var sdJwtParts = parts.Take(parts.Length - 1);
                var sdJwtString = string.Join("~", sdJwtParts) + "~";
                string sdJwtHash;
                try
                {
                    var sdJwtBytes = System.Text.Encoding.UTF8.GetBytes(sdJwtString);
                    var hashBytes = algorithm switch
                    {
                        HashAlgorithm.Sha256 => SHA256.HashData(sdJwtBytes),
                        HashAlgorithm.Sha384 => SHA384.HashData(sdJwtBytes),
                        HashAlgorithm.Sha512 => SHA512.HashData(sdJwtBytes),
                        _ => throw new SdJwtException("Unsupported SD-JWT hash algorithm", ErrorCode.UnsupportedAlgorithm)
                    };
                    sdJwtHash = Base64UrlEncoder.Encode(hashBytes);
                }
                catch (Exception ex)
                {
                    errors.Add(ErrorCode.InvalidInput);
                    errorDetails.Add($"Failed to compute SD-JWT hash: {ex.Message}");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }

                // Validate key binding JWT
                bool keyBindingValid = _keyBindingValidator.ValidateKeyBinding(
                    keyBindingJwt,
                    holderPublicKey,
                    sdJwtHash,
                    keyBindingAudiences,
                    _options.ExpectedNonce);

                if (!keyBindingValid)
                {
                    errors.Add(ErrorCode.InvalidSignature);
                    errorDetails.Add("Key binding JWT validation failed");
                }
            }
            else if (_options.RequireKeyBinding)
            {
                // Key binding is required but not present
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("Key binding is required but not present");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Reject all read-only validation failures before admitting a replay identifier.
            if (errors.Count > 0)
            {
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Reconstruction must also succeed before the stateful replay admission.
            var disclosedClaims = ExtractDisclosedClaims(jwt, disclosures, algorithm);
            cancellationToken.ThrowIfCancellationRequested();

            // Revocation can be a remote read. Do not contact the store for
            // invalid temporal/issuer/audience/digest/key-binding/reconstruction
            // results. Fully verified revoked tokens still fail before replay
            // admission and before returning disclosed claims to the caller.
            await CheckRevocationAsync(payload, header, errors, errorDetails, cancellationToken).ConfigureAwait(false);
            if (errors.Count > 0)
            {
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Step 6: Admit the verified presentation's replay identifier, if configured.
            if (_jtiValidator != null)
            {
                try
                {
                    // Extract claims from payload for JtiValidator
                    var claimsDict = new Dictionary<string, JsonElement>();
                    foreach (var property in payload.EnumerateObject())
                    {
                        claimsDict[property.Name] = property.Value;
                    }

                    await _jtiValidator.ValidateAsync(claimsDict, cancellationToken).ConfigureAwait(false);
                }
                catch (ReplayAttackException)
                {
                    // Re-throw replay attack exceptions directly
                    throw;
                }
                catch (SdJwtException)
                {
                    // Re-throw other SD-JWT exceptions (missing jti, missing iss, etc.)
                    throw;
                }
                catch (OperationCanceledException)
                {
                    // A canceled replay-cache admission must propagate to throwing
                    // async callers, not be mistaken for a malformed presentation.
                    throw;
                }
                catch (Exception ex)
                {
                    // Wrap unexpected exceptions
                    errors.Add(ErrorCode.InvalidInput);
                    errorDetails.Add($"Replay protection validation failed: {ex.Message}");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }
            }

            return new VerificationResult(disclosedClaims);
        }
        catch
        {
            throw;
        }
    }

    /// <summary>
    /// Extracts the hash algorithm from the JWT payload.
    /// Rejects unknown algorithms instead of silently defaulting to prevent downgrade attacks.
    /// </summary>
    private HashAlgorithm GetHashAlgorithm(JsonElement payload, HashAlgorithm? expectedHashAlgorithm)
    {
        // Default to SHA-256 per SD-JWT spec if _sd_alg claim is not present
        HashAlgorithm algorithm = HashAlgorithm.Sha256;

        if (payload.TryGetProperty("_sd_alg", out var sdAlgElement))
        {
            if (sdAlgElement.ValueKind != JsonValueKind.String)
            {
                throw new SdJwtException("SD-JWT _sd_alg must be a string", ErrorCode.InvalidInput);
            }

            var algString = sdAlgElement.GetString();
            algorithm = algString switch
            {
                "sha-256" => HashAlgorithm.Sha256,
                "sha-384" => HashAlgorithm.Sha384,
                "sha-512" => HashAlgorithm.Sha512,
                _ => throw new SdJwtException(
                    $"Unsupported hash algorithm: {algString}. Supported: sha-256, sha-384, sha-512",
                    ErrorCode.UnsupportedAlgorithm)
            };
        }

        // Configured policy cannot be overridden by a per-call constraint.
        if (_options.ExpectedHashAlgorithm.HasValue && algorithm != _options.ExpectedHashAlgorithm.Value)
        {
            throw new SdJwtException(
                $"Hash algorithm mismatch: configured policy requires {_options.ExpectedHashAlgorithm.Value}, got {algorithm}",
                ErrorCode.AlgorithmConfusion);
        }

        // Validate against an additional expected algorithm if specified.
        if (expectedHashAlgorithm.HasValue && algorithm != expectedHashAlgorithm.Value)
        {
            throw new SdJwtException(
                $"Hash algorithm mismatch: expected {expectedHashAlgorithm.Value}, got {algorithm}",
                ErrorCode.AlgorithmConfusion); // This will be caught and converted to HashAlgorithmMismatch
        }

        return algorithm;
    }

    /// <summary>
    /// Extracts disclosed claims from disclosures using full paths.
    /// Uses DisclosureClaimPathMapper to determine full paths by analyzing JWT structure.
    /// Supports both object property disclosures (3-element) and array element disclosures (2-element).
    /// </summary>
    private Dictionary<string, JsonElement> ExtractDisclosedClaims(
        string jwt,
        List<string> disclosures,
        HashAlgorithm algorithm)
    {
        var claims = new Dictionary<string, JsonElement>();

        if (disclosures.Count == 0)
        {
            return claims;
        }

        try
        {
            // Build claim path mapping using the mapper
            var sdJwt = new SdJwt(jwt, disclosures, algorithm);
            var mapper = new DisclosureClaimPathMapper();
            var claimPathToIndex = mapper.BuildClaimPathMapping(sdJwt);

            // Extract claim values using full paths
            // Skip intermediate objects that contain _sd arrays (they're reconstruction helpers, not actual claims)
            foreach (var (fullPath, disclosureIndex) in claimPathToIndex)
            {
                var disclosure = disclosures[disclosureIndex];
                var json = Base64UrlEncoder.DecodeString(disclosure);
                var array = JsonDocument.Parse(json).RootElement;

                if (array.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                var arrayLength = array.GetArrayLength();

                if (arrayLength == 3)
                {
                    // Object property disclosure: [salt, claim_name, claim_value]
                    var claimValue = array[2];

                    // Skip intermediate nested objects (those containing _sd arrays)
                    // These are needed for presentation but not for final disclosed claims
                    bool isIntermediateObject = claimValue.ValueKind == JsonValueKind.Object &&
                                               claimValue.TryGetProperty("_sd", out _);

                    if (!isIntermediateObject)
                    {
                        claims[fullPath] = claimValue;
                    }
                }
                else if (arrayLength == 2)
                {
                    // Array element disclosure: [salt, claim_value]
                    var claimValue = array[1];
                    claims[fullPath] = claimValue;
                }
            }
        }
        catch (Exception ex)
        {
            throw new SdJwtException("Disclosure reconstruction failed", ErrorCode.MalformedDisclosure, ex);
        }

        return claims;
    }

    /// <summary>
    /// Checks the unpadded, canonical base64url representation of a digest.
    /// Unpresented digest references (including decoys) must have the same
    /// encoded width and alphabet as a real digest for the selected hash.
    /// </summary>
    private static bool HasCanonicalDigestEncoding(string? digest, HashAlgorithm algorithm)
    {
        var expectedLength = algorithm switch
        {
            HashAlgorithm.Sha256 => 43,
            HashAlgorithm.Sha384 => 64,
            HashAlgorithm.Sha512 => 86,
            _ => 0
        };

        if (digest == null || digest.Length != expectedLength)
        {
            return false;
        }

        var lastSextet = 0;
        foreach (var character in digest)
        {
            lastSextet = character switch
            {
                >= 'A' and <= 'Z' => character - 'A',
                >= 'a' and <= 'z' => character - 'a' + 26,
                >= '0' and <= '9' => character - '0' + 52,
                '-' => 62,
                '_' => 63,
                _ => -1
            };

            if (lastSextet < 0)
            {
                return false;
            }
        }

        // SHA-256 (32 bytes) ends with 2 unused bits; SHA-512 (64 bytes)
        // ends with 4 unused bits. SHA-384 (48 bytes) fills all sextets.
        // Reject nonzero padding bits without decoding or allocating buffers.
        return algorithm switch
        {
            HashAlgorithm.Sha256 => (lastSextet & 0x03) == 0,
            HashAlgorithm.Sha384 => true,
            HashAlgorithm.Sha512 => (lastSextet & 0x0F) == 0,
            _ => false
        };
    }

    /// <summary>
    /// Recursively collects all _sd array digests from a JSON element.
    /// This supports nested selective disclosure structures per SD-JWT spec.
    /// </summary>
    private static bool CollectAllSdDigests(
        JsonElement element,
        List<Digest> digests,
        List<Digest> arrayDigests,
        HashAlgorithm algorithm,
        HashSet<string> seenDigests,
        int depth = 0,
        bool allowTopLevelSdAlg = false)
    {
        // Security: Prevent stack overflow with deeply nested structures
        const int MAX_NESTING_DEPTH = 10;
        if (depth > MAX_NESTING_DEPTH)
        {
            throw new ArgumentException($"Maximum nesting depth of {MAX_NESTING_DEPTH} exceeded during digest collection");
        }

        if (element.ValueKind == JsonValueKind.Object)
        {
            // The issuer's root claim names have already been checked. Nested
            // objects, including values inside Disclosures, must also be
            // unambiguous: duplicate JSON member names can be interpreted
            // differently by downstream claim consumers.
            if ((!allowTopLevelSdAlg || depth > 0) &&
                JsonObjectMemberGuard.HasInvalidOrDuplicateNames(element))
            {
                return false;
            }

            foreach (var property in element.EnumerateObject())
            {
                if (property.Name == "_sd")
                {
                    // RFC 9901: _sd must contain only string digests, each seen
                    // at most once across the signed payload and its Disclosures.
                    if (property.Value.ValueKind != JsonValueKind.Array)
                    {
                        return false;
                    }

                    foreach (var digestValue in property.Value.EnumerateArray())
                    {
                        if (digestValue.ValueKind != JsonValueKind.String)
                        {
                            return false;
                        }

                        var digest = digestValue.GetString();
                        if (digest == null || !HasCanonicalDigestEncoding(digest, algorithm) || !seenDigests.Add(digest))
                        {
                            return false;
                        }

                        digests.Add(new Digest(digest, algorithm));
                    }
                }
                else if (property.Name == "_sd_alg")
                {
                    // RFC 9901 allows _sd_alg only at the issuer JWT root.
                    // A Disclosure value is nested, even when parsed as an
                    // independent JSON subtree with depth zero.
                    if (!allowTopLevelSdAlg)
                    {
                        return false;
                    }
                }
                else
                {
                    // Recursively search nested objects and arrays (increment depth)
                    if (!CollectAllSdDigests(property.Value, digests, arrayDigests, algorithm, seenDigests, depth + 1))
                    {
                        return false;
                    }
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            // Recursively search array elements (increment depth)
            foreach (var item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object &&
                    item.TryGetProperty("...", out var arrayDigest))
                {
                    if (item.EnumerateObject().Count() != 1 ||
                        arrayDigest.ValueKind != JsonValueKind.String ||
                        !HasCanonicalDigestEncoding(arrayDigest.GetString(), algorithm))
                    {
                        return false;
                    }
                    var digestValue = arrayDigest.GetString()!;
                    if (!seenDigests.Add(digestValue))
                    {
                        return false;
                    }

                    var digest = new Digest(digestValue, algorithm);
                    digests.Add(digest);
                    arrayDigests.Add(digest);
                }

                if (!CollectAllSdDigests(item, digests, arrayDigests, algorithm, seenDigests, depth + 1))
                {
                    return false;
                }
            }
        }
        return true;
    }
    /// <summary>
    /// Checks if the token has been revoked via JTI, Key ID, or User ID.
    /// Called after all read-only validation and reconstruction, before replay admission.
    /// Only runs if a revocation store was provided.
    /// </summary>
    private async Task CheckRevocationAsync(
        JsonElement payload,
        JsonElement header,
        List<ErrorCode> errors,
        List<string> errorDetails,
        CancellationToken cancellationToken)
    {
        // Skip if no revocation store provided
        if (_revocationStore == null)
        {
            return;
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Check 1: JTI revocation (individual token blacklisting)
            if (payload.TryGetProperty("jti", out var jtiElement) && jtiElement.ValueKind == JsonValueKind.String)
            {
                var jti = jtiElement.GetString()!;
                var isRevoked = await _revocationStore.IsJtiRevokedAsync(jti, cancellationToken).ConfigureAwait(false);
                // Some stores return false even when cancellation arrives during the read.
                // Never admit the credential or consult subsequent backends after cancellation.
                cancellationToken.ThrowIfCancellationRequested();
                if (isRevoked)
                {
                    errors.Add(ErrorCode.TokenRevoked);
                    errorDetails.Add($"Token with JTI '{jti}' has been revoked");
                    throw new TokenRevokedException(jti);
                }
            }

            // Check 2: Key ID revocation (all tokens from signing key)
            if (header.TryGetProperty("kid", out var kidElement) && kidElement.ValueKind == JsonValueKind.String)
            {
                var keyId = kidElement.GetString()!;
                KeyIdGuard.EnsureValid(keyId);
                var isRevoked = await _revocationStore.IsKeyRevokedAsync(keyId, cancellationToken).ConfigureAwait(false);
                // Some stores return false even when cancellation arrives during the read.
                // Never admit the credential or consult subsequent backends after cancellation.
                cancellationToken.ThrowIfCancellationRequested();
                if (isRevoked)
                {
                    errors.Add(ErrorCode.TokenRevokedByKey);
                    errorDetails.Add($"Signing key '{keyId}' has been revoked");
                    throw new TokenRevokedException(keyId, RevocationReason.KeyRevoked);
                }
            }

            // Check 3: User ID revocation (all tokens for user)
            if (payload.TryGetProperty("sub", out var subElement) && subElement.ValueKind == JsonValueKind.String)
            {
                var userId = subElement.GetString()!;
                var isRevoked = await _revocationStore.IsUserRevokedAsync(userId, cancellationToken).ConfigureAwait(false);
                // Some stores return false even when cancellation arrives during the read.
                // Never admit the credential or consult subsequent backends after cancellation.
                cancellationToken.ThrowIfCancellationRequested();
                if (isRevoked)
                {
                    errors.Add(ErrorCode.TokenRevokedByUser);
                    var jti = payload.TryGetProperty("jti", out var j) && j.ValueKind == JsonValueKind.String
                        ? j.GetString()
                        : null;
                    errorDetails.Add($"User '{userId}' tokens have been revoked");
                    throw new TokenRevokedException(userId, RevocationReason.UserRevoked, jti);
                }
            }
        }
        catch (TokenRevokedException)
        {
            // Re-throw revocation exceptions
            throw;
        }
        catch (SdJwtException)
        {
            // Surface key-id validation failures directly (do not treat as revocation IO failure)
            throw;
        }
        catch (OperationCanceledException)
        {
            // Cancellation (including a revoked request or backend timeout) is
            // not a revocation-store outage to be admitted by fail-open policy.
            throw;
        }
        catch (Exception ex) when (_options.Revocation.FailureMode == RevocationFailureMode.FailOpen)
        {
            // Fail-open: Log error but allow token (availability over security)
            errorDetails.Add($"Revocation check failed but allowing token (fail-open mode): {ex.Message}");
        }
        catch (Exception ex)
        {
            // Fail-closed (default): Reject token on revocation check failure
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add($"Revocation check failed: {ex.Message}");
            throw new SdJwtException("Revocation check failed (fail-closed mode)", ErrorCode.InvalidInput, ex);
        }
    }

    private static IReadOnlyList<string> ExtractAudiences(JsonElement payload)
    {
        if (!payload.TryGetProperty("aud", out var audElement))
        {
            return [];
        }

        if (audElement.ValueKind == JsonValueKind.String)
        {
            var value = audElement.GetString();
            return string.IsNullOrWhiteSpace(value)
                ? []
                : [value];
        }

        if (audElement.ValueKind == JsonValueKind.Array)
        {
            var audiences = new List<string>();
            foreach (var item in audElement.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String &&
                    item.GetString() is { Length: > 0 } value)
                {
                    audiences.Add(value);
                }
            }

            return audiences;
        }

        return [];
    }

    private static IReadOnlyList<string> GetMatchingAudiences(
        IReadOnlyCollection<string> expectedAudiences,
        IReadOnlyCollection<string> actualAudiences)
    {
        if (expectedAudiences.Count == 0 || actualAudiences.Count == 0)
        {
            return [];
        }

        var expectedSet = new HashSet<string>(expectedAudiences, StringComparer.Ordinal);
        var matches = new List<string>();

        foreach (var audience in actualAudiences)
        {
            if (expectedSet.Contains(audience))
            {
                matches.Add(audience);
            }
        }

        return matches;
    }

    /// <summary>
    /// Scan at most the permitted number of presentation separators before
    /// allocating any component strings. Count-limited string.Split still
    /// collects every separator offset on .NET 8, even for malformed floods.
    /// </summary>
    private static string[]? SplitPresentationComponents(string presentation)
    {
        Span<int> positions = stackalloc int[Constants.MAX_DISCLOSURES + 1];
        var separatorCount = 0;
        var cursor = 0;

        while (true)
        {
            var separator = presentation.IndexOf('~', cursor);
            if (separator < 0)
            {
                break;
            }

            if (separatorCount == positions.Length)
            {
                return null;
            }

            positions[separatorCount++] = separator;
            cursor = separator + 1;
        }

        var parts = new string[separatorCount + 1];
        var start = 0;
        for (var i = 0; i < separatorCount; i++)
        {
            parts[i] = presentation[start..positions[i]];
            start = positions[i] + 1;
        }

        parts[separatorCount] = presentation[start..];
        return parts;
    }

    /// <summary>
    /// Ensures the JWT 'alg' header value aligns with the expected verification key type to prevent alg/key confusion.
    /// </summary>
    private static void ValidateAlgorithmAgainstKeyType(string alg, VerificationKeyType expectedKeyType)
    {
        if (string.IsNullOrWhiteSpace(alg))
        {
            throw new SdJwtException("JWT 'alg' claim cannot be empty", ErrorCode.InvalidInput);
        }

        bool isHmac = alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase);
        bool isAsymmetric =
            alg.StartsWith("RS", StringComparison.OrdinalIgnoreCase) ||
            alg.StartsWith("PS", StringComparison.OrdinalIgnoreCase) ||
            alg.StartsWith("ES", StringComparison.OrdinalIgnoreCase) ||
            alg.Equals("EdDSA", StringComparison.OrdinalIgnoreCase) ||
            alg.StartsWith("MLDSA", StringComparison.OrdinalIgnoreCase);

        // If expected is Either, do nothing and let signature validator enforce alg support.
        if (expectedKeyType == VerificationKeyType.Asymmetric && isHmac)
        {
            throw new SdJwtException(
                "HMAC-based algorithms (HS*) are not allowed when using asymmetric verification keys.",
                ErrorCode.AlgorithmConfusion);
        }

        if (expectedKeyType == VerificationKeyType.Symmetric && isAsymmetric)
        {
            throw new SdJwtException(
                "Asymmetric algorithms (RS/PS/ES/EdDSA/MLDSA) are not allowed when using symmetric verification keys.",
                ErrorCode.AlgorithmConfusion);
        }
    }
}
