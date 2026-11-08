using HeroSdJwt.Encoding;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace HeroSdJwt.AspNetCore.Authentication;

/// <summary>
/// Authentication handler for SD-JWT (Selective Disclosure JSON Web Token) authentication.
/// Handles extraction, verification, and claims mapping for SD-JWT presentations.
/// </summary>
public class SdJwtAuthenticationHandler : AuthenticationHandler<SdJwtAuthenticationOptions>
{
    private readonly ISdJwtVerifier _verifier;

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    /// <param name="verifier">The SD-JWT verifier service.</param>
#pragma warning disable CS9113 // Parameter is unread - required for ASP.NET Core compatibility
    public SdJwtAuthenticationHandler(
        IOptionsMonitor<SdJwtAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISdJwtVerifier verifier)
        : base(options, logger, encoder)
#pragma warning restore CS9113
    {
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
    }

    /// <summary>
    /// Handles the authentication request.
    /// Extracts the SD-JWT from the Authorization header, verifies it, and creates a ClaimsPrincipal.
    /// </summary>
    /// <returns>An <see cref="AuthenticateResult"/> indicating success or failure.</returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // An HTTP Authorization field must identify exactly one credential.
        // Joining repeated fields can hand an ambiguous token to an application
        // verifier factory (which might call KMS or other remote services).
        if (Request.Headers.Authorization.Count > 1)
        {
            return AuthenticateResult.Fail("Multiple Authorization values are not supported");
        }

        // Extract token from Authorization header
        string? token = ExtractTokenFromHeader();
        if (token == null)
        {
            Logger.LogDebug("No SD-JWT token found in Authorization header");
            return AuthenticateResult.NoResult();
        }

        // A proxy may coalesce duplicate Authorization fields with a comma.
        // Comma is not part of the SD-JWT compact serialization alphabet.
        if (token.Contains(','))
        {
            return AuthenticateResult.Fail("Invalid SD-JWT Authorization field");
        }

        // Every supported verifier enforces the 64-KiB combined presentation
        // wire budget. A custom policy factory may invoke external KMS or cache
        // services, so reject an impossible input before consulting it.
        // UTF-16 string length alone undercounts multi-byte UTF-8 input.
        if (token.Length > Constants.MAX_JWT_SIZE_BYTES ||
            (token.Length > Constants.MAX_JWT_SIZE_BYTES / 3 &&
             System.Text.Encoding.UTF8.GetByteCount(token) > Constants.MAX_JWT_SIZE_BYTES))
        {
            return AuthenticateResult.Fail("SD-JWT presentation exceeds maximum allowed size");
        }

        // Do not create a potentially remote-backed verifier for a credential
        // which cannot possibly be a compact JWS. Only examine the issuer JWT
        // before the first SD-JWT separator; a valid presentation may end in '~'.
        // Span slicing avoids allocating strings for hostile Authorization input.
        var jwtEnd = token.IndexOf('~');
        var jwt = token.AsSpan(0, jwtEnd >= 0 ? jwtEnd : token.Length);
        if (!HasPlausibleCompactJwt(jwt) ||
            token.AsSpan().IndexOfAny(" \t\r\n") >= 0)
        {
            return AuthenticateResult.Fail("Invalid SD-JWT compact serialization");
        }

        // An SD-JWT presentation needs the first '~' even without
        // Disclosures. Each intermediate slot must be a nonempty canonical
        // base64url Disclosure, and the number of those slots is bounded.
        // Leave the final slot to normal key-binding verification: it may be
        // empty or contain a compact KB-JWT with dots.
        if (jwtEnd < 0)
        {
            return AuthenticateResult.Fail("Invalid SD-JWT compact serialization");
        }

        var componentStart = jwtEnd + 1;
        var disclosureCount = 0;
        while (componentStart < token.Length)
        {
            var nextSeparator = token.IndexOf('~', componentStart);
            if (nextSeparator < 0)
            {
                break;
            }

            var disclosure = token.AsSpan(componentStart, nextSeparator - componentStart);
            if (disclosure.IsEmpty ||
                ++disclosureCount > Constants.MAX_DISCLOSURES ||
                disclosure.Length % 4 == 1 ||
                !HasOnlyBase64UrlCharacters(disclosure))
            {
                return AuthenticateResult.Fail("Invalid SD-JWT compact serialization");
            }

            componentStart = nextSeparator + 1;
        }

        // The final slot is either empty (no key binding) or a compact
        // KB-JWT. Reject impossible encodings without invoking a potentially
        // remote-backed verifier factory. A valid JWT is still fully checked
        // by the verifier after this cheap, allocation-free shape check.
        var keyBindingJwt = token.AsSpan(componentStart);
        if (!keyBindingJwt.IsEmpty && !HasPlausibleCompactJwt(keyBindingJwt))
        {
            return AuthenticateResult.Fail("Invalid SD-JWT compact serialization");
        }

        try
        {
            // A scheme verifier factory may perform KMS, database or network
            // work before creating the verifier. Do not invoke it for an
            // already-aborted HTTP request.
            Context.RequestAborted.ThrowIfCancellationRequested();

            // Verify the SD-JWT presentation (prefer async when available to avoid blocking caches/stores)
            VerificationResult result;
            if (_verifier is not ISdJwtVerifierFactory factory)
            {
                return AuthenticateResult.Fail(
                    "Custom SD-JWT verifiers must implement ISdJwtVerifierFactory to enforce authentication scheme VerificationOptions.");
            }

            var verifier = factory.CreateVerifier(Options.VerificationOptions);
            var asyncVerifier = verifier as ISdJwtVerifierAsync;

            if (Options.KeyResolver != null)
            {
                result = asyncVerifier is not null
                    ? await asyncVerifier.TryVerifyPresentationAsync(
                        token,
                        Options.KeyResolver,
                        Options.FallbackKey,
                        Options.VerificationOptions.ExpectedHashAlgorithm,
                        Context.RequestAborted).ConfigureAwait(false)
                    : verifier.TryVerifyPresentation(
                        token,
                        Options.KeyResolver,
                        Options.FallbackKey,
                        Options.VerificationOptions.ExpectedHashAlgorithm);
            }
            else if (Options.FallbackKey != null)
            {
                result = asyncVerifier is not null
                    ? await asyncVerifier.TryVerifyPresentationAsync(
                        token,
                        Options.FallbackKey,
                        Options.VerificationOptions.ExpectedHashAlgorithm,
                        Context.RequestAborted).ConfigureAwait(false)
                    : verifier.TryVerifyPresentation(
                        token,
                        Options.FallbackKey,
                        Options.VerificationOptions.ExpectedHashAlgorithm);
            }
            else
            {
                // This should never happen due to options validation, but handle defensively
                Logger.LogError("No key resolver or fallback key configured");
                return AuthenticateResult.Fail("Authentication configuration error: no key configured");
            }

            if (!result.IsValid)
            {
                // ErrorDetails may originate from application-provided verifiers
                // or external KMS/database services. Keep it out of public
                // authentication failures and routine logs.
                Logger.LogWarning(
                    "SD-JWT verification failed. Errors: {Errors}",
                    string.Join(", ", result.Errors));

                return AuthenticateResult.Fail("SD-JWT verification failed");
            }

            // Map both JWT payload claims and disclosed claims to ClaimsPrincipal
            var claims = MapAllClaimsToPrincipal(token, result);
            var identity = new ClaimsIdentity(claims, Scheme.Name, Options.NameClaimType, Options.RoleClaimType);
            var principal = new ClaimsPrincipal(identity);

            // Create authentication ticket
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            // Save token if configured
            if (Options.SaveToken)
            {
                ticket.Properties.StoreTokens(
                [
                    new AuthenticationToken { Name = "access_token", Value = token }
                ]);
            }

            Logger.LogInformation(
                "SD-JWT authentication succeeded for user with {ClaimCount} disclosed claims",
                result.DisclosedClaims.Count);

            return AuthenticateResult.Success(ticket);
        }
        catch (InvalidOperationException ex) when (
            string.Equals(
                ex.Message,
                "Derived verifiers must override ISdJwtVerifierFactory.CreateVerifier to preserve custom verification behavior.",
                StringComparison.Ordinal))
        {
            // Preserve the library's fixed, documented migration guidance.
            // Never forward an arbitrary provider exception message.
            Logger.LogWarning("A derived SD-JWT verifier did not override its policy factory.");
            return AuthenticateResult.Fail(
                "Derived verifiers must override ISdJwtVerifierFactory.CreateVerifier to preserve custom verification behavior.");
        }
        catch (OperationCanceledException) when (Context.RequestAborted.IsCancellationRequested)
        {
            // A client-disconnected request is not an invalid credential.
            // Preserve cancellation rather than logging it as a provider error.
            throw;
        }
        catch (Exception ex)
        {
            // An exception from a custom verifier/factory may contain secrets
            // in both its message and inner exception. Log only its type.
            Logger.LogError(
                "Exception occurred during SD-JWT authentication. Type: {ExceptionType}",
                ex.GetType().Name);
            return AuthenticateResult.Fail("SD-JWT authentication failed");
        }
    }

    // Check a compact JWS without splitting/allocating its segments.
    // This is only an admission preflight; cryptographic and canonical
    // encoding validation remain the verifier's responsibility.
    private static bool HasPlausibleCompactJwt(ReadOnlySpan<char> jwt)
    {
        var firstDot = jwt.IndexOf('.');
        var lastDot = jwt.LastIndexOf('.');
        return firstDot > 0 &&
            lastDot > firstDot + 1 &&
            lastDot != jwt.Length - 1 &&
            jwt[(firstDot + 1)..lastDot].IndexOf('.') < 0 &&
            HasOnlyBase64UrlCharacters(jwt[..firstDot]) &&
            HasOnlyBase64UrlCharacters(jwt[(firstDot + 1)..lastDot]) &&
            HasOnlyBase64UrlCharacters(jwt[(lastDot + 1)..]);
    }

    // A compact JWS segment may only use the unpadded base64url alphabet.
    // Checking the text before invoking a custom verifier factory avoids
    // needless external KMS/cache calls for impossible issuer JWTs without
    // decoding buffers or changing valid presentation semantics.
    private static bool HasOnlyBase64UrlCharacters(ReadOnlySpan<char> segment)
    {
        foreach (var character in segment)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character != '-' && character != '_')
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Extracts the SD-JWT token from the Authorization header.
    /// </summary>
    /// <returns>The token string if found; otherwise, null.</returns>
    private string? ExtractTokenFromHeader()
    {
        string? authorization = Request.Headers.Authorization.ToString();

        if (string.IsNullOrWhiteSpace(authorization))
        {
            return null;
        }

        // Check for "Bearer {token}" format
        if (!authorization.StartsWith(Options.TokenScheme + " ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // Extract token after scheme
        var token = authorization[(Options.TokenScheme.Length + 1)..].Trim();

        return string.IsNullOrWhiteSpace(token) ? null : token;
    }

    /// <summary>
    /// Maps both JWT payload claims and disclosed claims to ASP.NET Core claims.
    /// </summary>
    /// <param name="presentation">The SD-JWT presentation string.</param>
    /// <param name="result">The verification result containing disclosed claims.</param>
    /// <returns>A list of claims for the ClaimsPrincipal.</returns>
    private List<Claim> MapAllClaimsToPrincipal(string presentation, VerificationResult result)
    {
        var claims = new List<Claim>();

        // A verifier reporting success is not enough to issue an authentication
        // ticket if the issuer's payload cannot be projected. In particular,
        // swallowing a JSON/decoder failure here would authenticate a principal
        // missing its always-visible claims.
        // Only the issuer JWT payload is needed; do not copy disclosures.
        var jwtEnd = presentation.IndexOf('~');
        var jwt = presentation.AsSpan(0, jwtEnd >= 0 ? jwtEnd : presentation.Length);
        var firstDot = jwt.IndexOf('.');
        var lastDot = jwt.LastIndexOf('.');
        if (firstDot <= 0 || lastDot <= firstDot + 1 ||
            lastDot == jwt.Length - 1 ||
            jwt[(firstDot + 1)..lastDot].IndexOf('.') >= 0)
        {
            throw new JsonException("Verified JWT has an invalid compact payload.");
        }

        var payloadJson = Base64UrlEncoder.DecodeString(jwt[(firstDot + 1)..lastDot].ToString());
        using var payloadDocument = JsonDocument.Parse(payloadJson);
        var payload = payloadDocument.RootElement;
        if (payload.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("Verified JWT payload must be a JSON object.");
        }

        foreach (var property in payload.EnumerateObject())
        {
            // Skip SD-JWT-specific claims
            if (property.Name is "_sd" or "_sd_alg" or "cnf")
            {
                continue;
            }

            AddClaimFromJsonElement(claims, property.Name, property.Value);
        }

        // Add disclosed claims (selectively revealed claims)
        foreach (var (claimName, claimValue) in result.DisclosedClaims)
        {
            AddClaimFromJsonElement(claims, claimName, claimValue);
        }

        return claims;
    }

    /// <summary>
    /// Adds a claim from a JSON element, handling different value types and arrays.
    /// </summary>
    private void AddClaimFromJsonElement(List<Claim> claims, string claimName, JsonElement claimValue)
    {
        // Handle different JSON value types
        var claimValueString = claimValue.ValueKind switch
        {
            JsonValueKind.String => claimValue.GetString() ?? string.Empty,
            JsonValueKind.Number => claimValue.ToString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => string.Empty,
            JsonValueKind.Object => claimValue.GetRawText(),
            JsonValueKind.Array => claimValue.GetRawText(),
            JsonValueKind.Undefined => string.Empty,
            _ => claimValue.ToString()
        };

        // Handle array claims (roles, scopes, etc.) - add each element as separate claim
        if (claimValue.ValueKind is JsonValueKind.Array)
        {
            foreach (var arrayElement in claimValue.EnumerateArray())
            {
                var elementValue = arrayElement.ValueKind == JsonValueKind.String
                    ? arrayElement.GetString() ?? string.Empty
                    : arrayElement.ToString();

                claims.Add(new Claim(claimName, elementValue));
            }
        }
        else
        {
            claims.Add(new Claim(claimName, claimValueString));
        }
    }

    /// <summary>
    /// Handles authentication challenges (401 Unauthorized).
    /// Returns a minimal challenge response for API scenarios.
    /// </summary>
    /// <param name="properties">Authentication properties.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        // Request.Host can originate from an untrusted header. Encode it as a
        // quoted-string so it cannot add a second authentication parameter.
        var host = Request.Host.Value ?? string.Empty;
        if (host.Any(char.IsControl))
        {
            // realm is optional; omit it rather than emit an invalid header.
            Response.Headers.WWWAuthenticate = Options.TokenScheme;
        }
        else
        {
            var escapedRealm = host.Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("\"", "\\\"", StringComparison.Ordinal);
            Response.Headers.WWWAuthenticate = $"{Options.TokenScheme} realm=\"{escapedRealm}\"";
        }
        Response.StatusCode = 401;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Handles forbidden access (403 Forbidden).
    /// Returns a minimal forbidden response for API scenarios.
    /// </summary>
    /// <param name="properties">Authentication properties.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 403;
        return Task.CompletedTask;
    }
}
