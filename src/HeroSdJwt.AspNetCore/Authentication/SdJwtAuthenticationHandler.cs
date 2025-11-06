using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using HeroSdJwt.Encoding;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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
        // Extract token from Authorization header
        string? token = ExtractTokenFromHeader();
        if (token == null)
        {
            Logger.LogDebug("No SD-JWT token found in Authorization header");
            return AuthenticateResult.NoResult();
        }

        try
        {
            // Verify the SD-JWT presentation
            VerificationResult result;

            if (Options.KeyResolver != null)
            {
                // Use key resolver with optional fallback
                result = _verifier.TryVerifyPresentation(
                    token,
                    Options.KeyResolver,
                    Options.FallbackKey,
                    Options.VerificationOptions.ExpectedHashAlgorithm);
            }
            else if (Options.FallbackKey != null)
            {
                // Use fallback key only
                result = _verifier.TryVerifyPresentation(
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
                Logger.LogWarning(
                    "SD-JWT verification failed. Errors: {Errors}. Details: {Details}",
                    string.Join(", ", result.Errors),
                    result.ErrorDetails);

                return AuthenticateResult.Fail($"SD-JWT verification failed: {result.ErrorDetails}");
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
                ticket.Properties.StoreTokens(new[]
                {
                    new AuthenticationToken { Name = "access_token", Value = token }
                });
            }

            Logger.LogInformation(
                "SD-JWT authentication succeeded for user with {ClaimCount} disclosed claims",
                result.DisclosedClaims.Count);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Exception occurred during SD-JWT authentication");
            return AuthenticateResult.Fail($"Authentication error: {ex.Message}");
        }
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
        var token = authorization.Substring(Options.TokenScheme.Length + 1).Trim();

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

        // Extract JWT payload claims (always visible claims like sub, iss, aud, name, role, etc.)
        try
        {
            var parts = presentation.Split('~');
            if (parts.Length > 0)
            {
                var jwt = parts[0];
                var jwtParts = jwt.Split('.');
                if (jwtParts.Length == 3)
                {
                    var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
                    var payload = JsonDocument.Parse(payloadJson).RootElement;

                    foreach (var property in payload.EnumerateObject())
                    {
                        // Skip SD-JWT-specific claims
                        if (property.Name == "_sd" || property.Name == "_sd_alg" || property.Name == "cnf")
                        {
                            continue;
                        }

                        AddClaimFromJsonElement(claims, property.Name, property.Value);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "Failed to extract JWT payload claims");
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
            System.Text.Json.JsonValueKind.String => claimValue.GetString() ?? string.Empty,
            System.Text.Json.JsonValueKind.Number => claimValue.ToString(),
            System.Text.Json.JsonValueKind.True => "true",
            System.Text.Json.JsonValueKind.False => "false",
            System.Text.Json.JsonValueKind.Null => string.Empty,
            System.Text.Json.JsonValueKind.Object => claimValue.GetRawText(),
            System.Text.Json.JsonValueKind.Array => claimValue.GetRawText(),
            _ => claimValue.ToString()
        };

        // Handle array claims (roles, scopes, etc.) - add each element as separate claim
        if (claimValue.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            foreach (var arrayElement in claimValue.EnumerateArray())
            {
                var elementValue = arrayElement.ValueKind == System.Text.Json.JsonValueKind.String
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
        Response.Headers.WWWAuthenticate = $"{Options.TokenScheme} realm=\"{Request.Host}\"";
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
