using HeroSdJwt.Common;
using HeroSdJwt.Core;
using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Verification;

/// <summary>
/// Verifies SD-JWT presentations by validating signatures, digests, and claims.
/// Implements security measures including constant-time comparison, algorithm confusion prevention,
/// and timing attack resistance.
/// </summary>
public class SdJwtVerifier
{
    private readonly SdJwtVerificationOptions _options;

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
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
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
    /// Verifies an SD-JWT presentation without throwing exceptions.
    /// Returns a result object with validation status and errors.
    /// </summary>
    /// <param name="presentation">The combined SD-JWT presentation string.</param>
    /// <param name="publicKey">The public key or shared secret for signature verification.</param>
    /// <param name="expectedHashAlgorithm">Optional expected hash algorithm.</param>
    /// <returns>Verification result with validation status, errors, and disclosed claims.</returns>
    public VerificationResult VerifyPresentationSafe(
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
        if (presentation.Length > Core.Constants.MaxJwtSizeBytes)
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add($"Presentation exceeds maximum allowed size of {Core.Constants.MaxJwtSizeBytes} bytes");
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
        if (jwt.Length > Core.Constants.MaxJwtSizeBytes / 2)
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
                if (disclosures.Count >= Core.Constants.MaxDisclosures)
                {
                    errors.Add(ErrorCode.InvalidInput);
                    errorDetails.Add($"Too many disclosures: exceeds maximum of {Core.Constants.MaxDisclosures}");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }

                disclosures.Add(parts[i]);
            }
        }

        // Step 1: Verify JWT signature
        bool signatureValid = false;
        try
        {
            signatureValid = SignatureValidator.VerifyJwtSignature(jwt, publicKey);
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
        bool claimsValid = ClaimValidator.ValidateTemporalClaims(payload, _options);
        if (!claimsValid)
        {
            errors.Add(ErrorCode.TokenExpired);
            errorDetails.Add("Temporal claims validation failed");
        }

        // Validate issuer if configured
        if (!ClaimValidator.ValidateIssuer(payload, _options.ExpectedIssuer))
        {
            errors.Add(ErrorCode.InvalidInput);
            errorDetails.Add("Issuer validation failed");
        }

        // Validate audience if configured
        if (!ClaimValidator.ValidateAudience(payload, _options.ExpectedAudience))
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

        if (payload.TryGetProperty("_sd", out var sdElement) &&
            sdElement.ValueKind == JsonValueKind.Array)
        {
            var expectedDigests = new List<Digest>();
            foreach (var digestValue in sdElement.EnumerateArray())
            {
                if (digestValue.ValueKind == JsonValueKind.String)
                {
                    expectedDigests.Add(new Digest(digestValue.GetString()!, algorithm));
                }
            }

            if (disclosures.Count > 0)
            {
                bool digestsValid = DigestValidator.ValidateAllDigests(disclosures, expectedDigests, algorithm);
                if (!digestsValid)
                {
                    errors.Add(ErrorCode.DigestMismatch);
                    errorDetails.Add("Disclosure digest validation failed");
                }
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
                var jwkBase64 = jwkElement.GetString();
                if (string.IsNullOrWhiteSpace(jwkBase64))
                {
                    errors.Add(ErrorCode.InvalidInput);
                    errorDetails.Add("Invalid cnf claim: jwk is empty");
                    return new VerificationResult(errors, string.Join("; ", errorDetails));
                }
                holderPublicKey = Convert.FromBase64String(jwkBase64);

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
                errorDetails.Add("Invalid cnf claim: jwk is not valid Base64");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }
            catch (CryptographicException)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add("Invalid cnf claim: jwk is not a valid ECDSA public key");
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
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(sdJwtString));
                sdJwtHash = Base64UrlEncoder.Encode(hashBytes);
            }
            catch (Exception ex)
            {
                errors.Add(ErrorCode.InvalidInput);
                errorDetails.Add($"Failed to compute SD-JWT hash: {ex.Message}");
                return new VerificationResult(errors, string.Join("; ", errorDetails));
            }

            // Validate key binding JWT
            bool keyBindingValid = KeyBindingValidator.ValidateKeyBinding(
                keyBindingJwt,
                holderPublicKey,
                sdJwtHash,
                _options.ExpectedAudience,
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

        // Step 6: Extract disclosed claims
        var disclosedClaims = ExtractDisclosedClaims(disclosures);

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
    /// Extracts disclosed claims from disclosures.
    /// Invalid disclosures are tracked but not included in the result.
    /// </summary>
    private Dictionary<string, JsonElement> ExtractDisclosedClaims(List<string> disclosures)
    {
        var claims = new Dictionary<string, JsonElement>();
        var invalidDisclosureCount = 0;

        foreach (var disclosure in disclosures)
        {
            try
            {
                var json = Base64UrlEncoder.DecodeString(disclosure);
                var array = JsonDocument.Parse(json).RootElement;

                if (array.ValueKind == JsonValueKind.Array && array.GetArrayLength() == 3)
                {
                    var claimName = array[1].GetString();
                    var claimValue = array[2];

                    if (!string.IsNullOrWhiteSpace(claimName))
                    {
                        claims[claimName] = claimValue;
                    }
                    else
                    {
                        invalidDisclosureCount++;
                    }
                }
                else
                {
                    invalidDisclosureCount++;
                }
            }
            catch
            {
                // Track invalid disclosures for security monitoring
                // In production, this should be logged for analysis
                invalidDisclosureCount++;
            }
        }

        // Note: In production systems, invalidDisclosureCount should be logged
        // for security monitoring to detect potential tampering attempts
        // For now, we silently ignore to prevent information disclosure

        return claims;
    }
}
