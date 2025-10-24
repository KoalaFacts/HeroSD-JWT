using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using Constants = HeroSdJwt.Primitives.Constants;
using ErrorCode = HeroSdJwt.Primitives.ErrorCode;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Verification;

/// <summary>
/// Verifies SD-JWT presentations by validating signatures, digests, and claims.
/// Implements security measures including constant-time comparison, algorithm confusion prevention,
/// and timing attack resistance.
/// </summary>
public class SdJwtVerifier
{
    private readonly SdJwtVerificationOptions options;
    private readonly IEcPublicKeyConverter ecPublicKeyConverter;
    private readonly ISignatureValidator signatureValidator;
    private readonly IDigestValidator digestValidator;
    private readonly IKeyBindingValidator keyBindingValidator;
    private readonly IClaimValidator claimValidator;

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtVerifier"/> class with default options.
    /// </summary>
    public SdJwtVerifier()
        : this(new SdJwtVerificationOptions())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtVerifier"/> class with specified options.
    /// </summary>
    /// <param name="options">Verification options.</param>
    public SdJwtVerifier(SdJwtVerificationOptions options)
        : this(
            options,
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(),
            new ClaimValidator())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtVerifier"/> class with dependencies.
    /// </summary>
    public SdJwtVerifier(
        SdJwtVerificationOptions options,
        IEcPublicKeyConverter ecPublicKeyConverter,
        ISignatureValidator signatureValidator,
        IDigestValidator digestValidator,
        IKeyBindingValidator keyBindingValidator,
        IClaimValidator claimValidator)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signatureValidator);
        ArgumentNullException.ThrowIfNull(digestValidator);
        ArgumentNullException.ThrowIfNull(keyBindingValidator);
        ArgumentNullException.ThrowIfNull(claimValidator);

        options.Validate();
        this.options = options;
        this.ecPublicKeyConverter = ecPublicKeyConverter;
        this.signatureValidator = signatureValidator;
        this.digestValidator = digestValidator;
        this.keyBindingValidator = keyBindingValidator;
        this.claimValidator = claimValidator;
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

        var result = VerifyPresentationInternal(presentation, publicKey, expectedHashAlgorithm);

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
            return VerifyPresentationInternal(presentation, publicKey, expectedHashAlgorithm);
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
        Primitives.KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(presentation);

        var result = VerifyPresentationInternalWithResolver(presentation, keyResolver, fallbackKey, expectedHashAlgorithm);

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
        Primitives.KeyResolver? keyResolver,
        byte[]? fallbackKey = null,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(presentation);

        try
        {
            return VerifyPresentationInternalWithResolver(presentation, keyResolver, fallbackKey, expectedHashAlgorithm);
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
    /// Internal verification logic with key resolver support.
    /// </summary>
    private VerificationResult VerifyPresentationInternalWithResolver(
        string presentation,
        Primitives.KeyResolver? keyResolver,
        byte[]? fallbackKey,
        HashAlgorithm? expectedHashAlgorithm)
    {
        var errors = new List<ErrorCode>();
        var errorDetails = new List<string>();

        // Validate presentation size to prevent DoS attacks
        if (presentation.Length > Constants.MaxJwtSizeBytes)
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add($"Presentation exceeds maximum allowed size of {Constants.MaxJwtSizeBytes} bytes");
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

                if (string.IsNullOrWhiteSpace(keyId))
                {
                    throw new SdJwtException("JWT header contains empty 'kid' claim", ErrorCode.InvalidInput);
                }

                // Use resolver
                if (keyResolver == null)
                {
                    throw new SdJwtException(
                        "JWT contains 'kid' parameter but no key resolver was provided",
                        ErrorCode.KeyResolverMissing);
                }

                try
                {
                    verificationKey = keyResolver(keyId)!;
                    if (verificationKey == null)
                    {
                        throw new SdJwtException(
                            $"Key resolver could not find key for kid '{keyId}'",
                            ErrorCode.KeyIdNotFound);
                    }
                }
                catch (SdJwtException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    throw new SdJwtException(
                        $"Key resolver threw an exception while resolving kid '{keyId}': {ex.Message}",
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
        return VerifyPresentationInternal(presentation, verificationKey, expectedHashAlgorithm);
    }

    /// <summary>
    /// Internal verification logic shared by both throwing and non-throwing methods.
    /// </summary>
    private VerificationResult VerifyPresentationInternal(
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm)
    {
        var errors = new List<ErrorCode>();
        var errorDetails = new List<string>();

        // Validate presentation size to prevent DoS attacks
        if (presentation.Length > Constants.MaxJwtSizeBytes)
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add($"Presentation exceeds maximum allowed size of {Constants.MaxJwtSizeBytes} bytes");
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
        if (jwt.Length > Constants.MaxJwtSizeBytes / 2)
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
            if (!string.IsNullOrWhiteSpace(parts[i]))
            {
                if (disclosures.Count >= Constants.MaxDisclosures)
                {
                    errors.Add(ErrorCode.InvalidInput);
                    errorDetails.Add($"Too many disclosures: exceeds maximum of {Constants.MaxDisclosures}");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }

                disclosures.Add(parts[i]);
            }
        }

        // Step 1: Verify JWT signature
        bool signatureValid = false;
        try
        {
            signatureValid = signatureValidator.VerifyJwtSignature(jwt, publicKey);
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
        var jwtParts = jwt.Split('.');
        if (jwtParts.Length != 3)
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add("Invalid JWT format");
            return new VerificationResult(errors, string.Join("; ", errorDetails));
        }

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

        // Step 3: Validate temporal claims (exp, nbf, iat)
        bool claimsValid = claimValidator.ValidateTemporalClaims(payload, options);
        if (!claimsValid)
        {
            errors.Add(ErrorCode.TokenExpired);
            errorDetails.Add("Temporal claims validation failed");
        }

        // Validate issuer if configured
        if (!claimValidator.ValidateIssuer(payload, options.ExpectedIssuer))
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add("Issuer validation failed");
        }

        // Validate audience if configured
        if (!claimValidator.ValidateAudience(payload, options.ExpectedAudience))
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
            bool digestsValid = digestValidator.ValidateAllDigests(disclosures, expectedDigests, algorithm);
            if (!digestsValid)
            {
                errors.Add(ErrorCode.DigestMismatch);
                errorDetails.Add("Disclosure digest validation failed");
            }
        }

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
                    holderPublicKey = ecPublicKeyConverter.FromJwk(jwkElement);
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
            bool keyBindingValid = keyBindingValidator.ValidateKeyBinding(
                keyBindingJwt,
                holderPublicKey,
                sdJwtHash,
                options.ExpectedAudience,
                options.ExpectedNonce);

            if (!keyBindingValid)
            {
                errors.Add(ErrorCode.InvalidSignature);
                errorDetails.Add("Key binding JWT validation failed");
            }
        }
        else if (options.RequireKeyBinding)
        {
            // Key binding is required but not present
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add("Key binding is required but not present");
            return new VerificationResult(errors, string.Join("; ", errorDetails));
        }

        // Step 6: Extract disclosed claims with full paths
        var disclosedClaims = ExtractDisclosedClaims(jwt, disclosures, algorithm);

        // Return result
        if (errors.Count > 0)
        {
            return new VerificationResult(errors, string.Join("; ", errorDetails));
        }

        return new VerificationResult(disclosedClaims);
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
        const int MaxNestingDepth = 10;
        if (depth > MaxNestingDepth)
        {
            throw new ArgumentException($"Maximum nesting depth of {MaxNestingDepth} exceeded during digest collection");
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
}
