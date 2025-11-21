using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.Mvc;
using MultiTenantAuthExample.Models;
using MultiTenantAuthExample.Services;

namespace MultiTenantAuthExample.Controllers;

/// <summary>
/// Multi-tenant SD-JWT token operations (issuance and verification).
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class TokensController(
    ITenantService tenantService,
    ISdJwtIssuer issuer,
    ISdJwtVerifier verifier,
    ILogger<TokensController> logger) : ControllerBase
{
    private readonly ITenantService _tenantService = tenantService;
    private readonly ISdJwtIssuer _issuer = issuer;
    private readonly ISdJwtVerifier _verifier = verifier;
    private readonly ILogger<TokensController> _logger = logger;

    /// <summary>
    /// Issues a new SD-JWT for a specific tenant.
    /// </summary>
    /// <param name="request">Token issuance request with tenant context.</param>
    /// <returns>SD-JWT in combined format with metadata.</returns>
    /// <response code="200">Token issued successfully</response>
    /// <response code="400">Invalid request or tenant not found</response>
    [HttpPost("issue")]
    [ProducesResponseType(typeof(TokenIssueResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    public IActionResult IssueToken([FromBody] TokenIssueRequest request)
    {
        // Validate tenant
        if (!_tenantService.IsTenantValid(request.TenantId))
        {
            _logger.LogWarning("Token issuance failed: Invalid tenant {TenantId}", request.TenantId);
            return BadRequest(new ProblemDetails
            {
                Title = "Invalid Tenant",
                Detail = $"Tenant '{request.TenantId}' not found or inactive",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var tenant = _tenantService.GetTenant(request.TenantId)!;
        var signingKey = _tenantService.GetCurrentSigningKey(request.TenantId);

        if (signingKey == null)
        {
            _logger.LogError("No signing key available for tenant {TenantId}", request.TenantId);
            return Problem("Signing key not available for tenant", statusCode: StatusCodes.Status500InternalServerError);
        }

        try
        {
            // Build claims with tenant context
            var claims = new Dictionary<string, object>(request.Claims)
            {
                ["sub"] = request.Subject,
                ["iss"] = $"https://example.com/tenants/{request.TenantId}",
                ["tenant_id"] = request.TenantId,
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };

            // Add expiration
            var lifetimeSeconds = request.TokenLifetimeSeconds
                ?? tenant.MaxTokenLifetimeSeconds
                ?? 3600; // Default 1 hour
            var expiresAt = DateTimeOffset.UtcNow.AddSeconds(lifetimeSeconds).ToUnixTimeSeconds();
            claims["exp"] = expiresAt;

            // Merge tenant default claims (if any)
            if (tenant.DefaultClaims != null)
            {
                foreach (var (key, value) in tenant.DefaultClaims)
                {
                    if (!claims.ContainsKey(key))
                    {
                        claims[key] = value;
                    }
                }
            }

            // Issue SD-JWT with tenant's current key
            var sdJwt = _issuer.CreateSdJwt(
                claims,
                request.SelectivelyDisclosableClaims ?? [],
                signingKey,
                HashAlgorithm.Sha256,
                SignatureAlgorithm.HS256,
                keyId: tenant.CurrentKeyId  // Include kid for key rotation support
            );

            _logger.LogInformation(
                "Issued SD-JWT for tenant {TenantId}, subject {Subject}, key {KeyId}, {DisclosureCount} disclosures",
                request.TenantId, request.Subject, tenant.CurrentKeyId, sdJwt.Disclosures.Count);

            return Ok(new TokenIssueResponse
            {
                SdJwt = sdJwt.ToCombinedFormat(),
                TenantId = request.TenantId,
                KeyId = tenant.CurrentKeyId,
                ExpiresAt = expiresAt,
                SelectivelyDisclosableClaims = request.SelectivelyDisclosableClaims ?? []
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to issue token for tenant {TenantId}", request.TenantId);
            return Problem("Token issuance failed", statusCode: StatusCodes.Status500InternalServerError);
        }
    }

    /// <summary>
    /// Verifies an SD-JWT presentation with tenant-aware key resolution.
    /// </summary>
    /// <param name="request">Verification request with presentation and optional tenant hint.</param>
    /// <returns>Verification result with disclosed claims.</returns>
    /// <response code="200">Verification completed (check IsValid field)</response>
    /// <response code="400">Invalid request format</response>
    [HttpPost("verify")]
    [ProducesResponseType(typeof(TokenVerifyResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    public IActionResult VerifyToken([FromBody] TokenVerifyRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Presentation))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Invalid Request",
                Detail = "Presentation is required",
                Status = StatusCodes.Status400BadRequest
            });
        }

        try
        {
            // Extract tenant from JWT payload if not provided
            string? tenantId = request.TenantId;
            string? keyId = null;

            if (string.IsNullOrEmpty(tenantId))
            {
                // Parse JWT to extract tenant_id claim
                var parts = request.Presentation.Split('~');
                if (parts.Length > 0)
                {
                    var jwtParts = parts[0].Split('.');
                    if (jwtParts.Length == 3)
                    {
                        try
                        {
                            var payloadJson = System.Text.Encoding.UTF8.GetString(
                                Convert.FromBase64String(AddBase64Padding(jwtParts[1].Replace('-', '+').Replace('_', '/'))));

                            using var doc = System.Text.Json.JsonDocument.Parse(payloadJson);
                            if (doc.RootElement.TryGetProperty("tenant_id", out var tenantIdElement))
                            {
                                tenantId = tenantIdElement.GetString();
                            }

                            // Also extract kid from header if present
                            var headerJson = System.Text.Encoding.UTF8.GetString(
                                Convert.FromBase64String(AddBase64Padding(jwtParts[0].Replace('-', '+').Replace('_', '/'))));
                            using var headerDoc = System.Text.Json.JsonDocument.Parse(headerJson);
                            if (headerDoc.RootElement.TryGetProperty("kid", out var kidElement))
                            {
                                keyId = kidElement.GetString();
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Failed to extract tenant_id from JWT payload");
                        }
                    }
                }
            }

            if (string.IsNullOrEmpty(tenantId))
            {
                _logger.LogWarning("Could not determine tenant for verification");
                return Ok(new TokenVerifyResponse
                {
                    IsValid = false,
                    Errors = ["Could not determine tenant from presentation"]
                });
            }

            if (!_tenantService.IsTenantValid(tenantId))
            {
                _logger.LogWarning("Verification failed: Invalid tenant {TenantId}", tenantId);
                return Ok(new TokenVerifyResponse
                {
                    IsValid = false,
                    TenantId = tenantId,
                    Errors = [$"Tenant '{tenantId}' not found or inactive"]
                });
            }

            // Create tenant-specific key resolver
            var keyResolver = _tenantService.CreateKeyResolver(tenantId);

            // Verify with key rotation support
            var result = _verifier.TryVerifyPresentation(
                request.Presentation,
                keyResolver: keyResolver,
                fallbackKey: _tenantService.GetCurrentSigningKey(tenantId) // For tokens without kid
            );

            if (result.IsValid)
            {
                _logger.LogInformation(
                    "Successfully verified SD-JWT for tenant {TenantId}, key {KeyId}, {ClaimCount} claims disclosed",
                    tenantId, keyId ?? "unknown", result.DisclosedClaims.Count);
            }
            else
            {
                _logger.LogWarning(
                    "Verification failed for tenant {TenantId}: {Errors}",
                    tenantId, string.Join(", ", result.Errors));
            }

            return Ok(new TokenVerifyResponse
            {
                IsValid = result.IsValid,
                TenantId = tenantId,
                KeyId = keyId,
                DisclosedClaims = result.IsValid ? result.DisclosedClaims : null,
                Errors = result.IsValid ? null : [.. result.Errors.Select(e => e.ToString())]
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Verification error");
            return Ok(new TokenVerifyResponse
            {
                IsValid = false,
                Errors = ["Internal verification error"]
            });
        }
    }

    /// <summary>
    /// Lists all configured tenants.
    /// </summary>
    /// <returns>List of tenant information.</returns>
    [HttpGet("tenants")]
    [ProducesResponseType(typeof(IEnumerable<object>), StatusCodes.Status200OK)]
    public IActionResult GetTenants()
    {
        var tenants = _tenantService.GetAllTenants().Select(t => new
        {
            t.TenantId,
            t.TenantName,
            t.CurrentKeyId,
            AvailableKeys = t.SigningKeys.Keys.ToArray(),
            t.IsActive
        });

        return Ok(tenants);
    }

    private static string AddBase64Padding(string base64)
    {
        var padding = (4 - (base64.Length % 4)) % 4;
        return base64 + new string('=', padding);
    }
}
