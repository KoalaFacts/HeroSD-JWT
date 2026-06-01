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
/// </summary>
public class SdJwtVerifier : ISdJwtVerifier, ISdJwtVerifierAsync
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
        var parts = presentation.Split('~');
        if (parts.Length < 2)
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add("Invalid presentation format: expected at least JWT and empty slots");
            return new VerificationResult(errors, string.Join("; ", errorDetails));
        }

        var jwt = parts[0];

        // Step 1: Extract kid from JWT header and resolve to verification key
        byte[] verificationKey;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Parse JWT header to check for kid
            var jwtParts = jwt.Split('.');
            if (jwtParts.Length != 3)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("Invalid JWT format");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            var headerJson = Base64UrlEncoder.DecodeString(jwtParts[0]);
            var header = JsonDocument.Parse(headerJson).RootElement;

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
            var parts = presentation.Split('~');
            if (parts.Length < 2)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("Invalid presentation format: expected at least JWT and empty slots");
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

                    disclosures.Add(parts[i]);
                }
            }

            // Parse JWT structure up front
            var jwtParts = jwt.Split('.');
            if (jwtParts.Length != 3)
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
                errors.Add(ErrorCode.InvalidSignature);
                errorDetails.Add("JWT signature is invalid");
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

            // Step 3.5: Check token revocation (JTI, Key ID, User ID)
            // Inserted after temporal/issuer/audience validation, before digest validation
            // Per research.md: Early rejection saves CPU on expensive cryptographic operations
            await CheckRevocationAsync(payload, header, errors, errorDetails, cancellationToken).ConfigureAwait(false);

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
            CollectAllSdDigests(payload, expectedDigests, algorithm);

            // Also collect _sd digests from disclosure values (for nested structures)
            foreach (var disclosure in disclosures)
            {
                try
                {
                    var json = Base64UrlEncoder.DecodeString(disclosure);
                    var array = JsonDocument.Parse(json).RootElement;

                    if (array.ValueKind == JsonValueKind.Array && array.GetArrayLength() >= 2)
                    {
                        // For 3-element disclosures, check if the value contains _sd arrays
                        var valueIndex = array.GetArrayLength() == 3 ? 2 : 1;
                        var value = array[valueIndex];
                        CollectAllSdDigests(value, expectedDigests, algorithm);
                    }
                }
                catch
                {
                    // Skip malformed disclosures
                }
            }

            if (disclosures.Count > 0 && expectedDigests.Count > 0)
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
                    if (ecdsa.KeySize != 256)
                    {
                        errors.Add(ErrorCode.UnsupportedAlgorithm);
                        errorDetails.Add($"Unsupported elliptic curve: only P-256 is supported, got {ecdsa.KeySize}-bit key");
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
                    using var sha256 = SHA256.Create();
                    var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(sdJwtString));
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

            // Step 5.5: Validate replay protection (jti) if JtiValidator is present
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
                catch (Exception ex)
                {
                    // Wrap unexpected exceptions
                    errors.Add(ErrorCode.InvalidInput);
                    errorDetails.Add($"Replay protection validation failed: {ex.Message}");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }
            }

            // Step 6: Extract disclosed claims with full paths
            var disclosedClaims = ExtractDisclosedClaims(jwt, disclosures, algorithm);

            // Return result
            return errors.Count > 0
                ? new VerificationResult(errors, string.Join("; ", errorDetails))
                : new VerificationResult(disclosedClaims);
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
            var algString = sdAlgElement.GetString();
            algorithm = algString?.ToLowerInvariant() switch
            {
                "sha-256" => HashAlgorithm.Sha256,
                "sha-384" => HashAlgorithm.Sha384,
                "sha-512" => HashAlgorithm.Sha512,
                _ => throw new SdJwtException(
                    $"Unsupported hash algorithm: {algString}. Supported: sha-256, sha-384, sha-512",
                    ErrorCode.UnsupportedAlgorithm)
            };
        }

        // Validate against expected algorithm if specified
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
                try
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
                catch
                {
                    // Skip invalid disclosures
                }
            }
        }
        catch
        {
            // If mapping fails, return empty claims dictionary
            // This can happen with malformed JWT or disclosures
        }

        return claims;
    }

    /// <summary>
    /// Recursively collects all _sd array digests from a JSON element.
    /// This supports nested selective disclosure structures per SD-JWT spec.
    /// </summary>
    private static void CollectAllSdDigests(JsonElement element, List<Digest> digests, HashAlgorithm algorithm, int depth = 0)
    {
        // Security: Prevent stack overflow with deeply nested structures
        const int MAX_NESTING_DEPTH = 10;
        if (depth > MAX_NESTING_DEPTH)
        {
            throw new ArgumentException($"Maximum nesting depth of {MAX_NESTING_DEPTH} exceeded during digest collection");
        }

        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (property.Name == "_sd" && property.Value.ValueKind == JsonValueKind.Array)
                {
                    // Found an _sd array - collect all digests
                    foreach (var digestValue in property.Value.EnumerateArray())
                    {
                        if (digestValue.ValueKind == JsonValueKind.String)
                        {
                            digests.Add(new Digest(digestValue.GetString()!, algorithm));
                        }
                    }
                }
                else if (property.Name != "_sd_alg")
                {
                    // Recursively search nested objects and arrays (increment depth)
                    CollectAllSdDigests(property.Value, digests, algorithm, depth + 1);
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            // Recursively search array elements (increment depth)
            foreach (var item in element.EnumerateArray())
            {
                CollectAllSdDigests(item, digests, algorithm, depth + 1);
            }
        }
    }
    /// <summary>
    /// Checks if the token has been revoked via JTI, Key ID, or User ID.
    /// Called after temporal claims validation, before digest validation.
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
