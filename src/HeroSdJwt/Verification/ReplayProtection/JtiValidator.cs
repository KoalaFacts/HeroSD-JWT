using HeroSdJwt.Exceptions;
using System.Text.Json;

namespace HeroSdJwt.Verification.ReplayProtection;

/// <summary>
/// Validates JWT ID (jti) claims to prevent replay attacks.
/// Integrates with IJtiCache to track seen tokens.
/// </summary>
public class JtiValidator
{
    private readonly IJtiCache _cache;
    private readonly ReplayProtectionOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="JtiValidator"/> class.
    /// </summary>
    /// <param name="cache">The cache implementation for tracking JWT IDs.</param>
    /// <param name="options">Configuration options for replay protection.</param>
    /// <exception cref="ArgumentNullException">Thrown when cache or options is null.</exception>
    public JtiValidator(IJtiCache cache, ReplayProtectionOptions options)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Validates jti claim and checks for replay attacks.
    /// </summary>
    /// <param name="claims">JWT payload claims.</param>
    /// <param name="cancellationToken">Cancellation token for async operations.</param>
    /// <exception cref="SdJwtException">If jti is missing when required or validation fails.</exception>
    /// <exception cref="ReplayAttackException">If jti has already been used.</exception>
    public async Task ValidateAsync(Dictionary<string, JsonElement> claims, CancellationToken cancellationToken = default)
    {
        // If replay protection disabled, skip validation
        if (!_options.Enabled)
        {
            return;
        }

        // Extract issuer (required for cache key)
        if (!claims.TryGetValue("iss", out var issElement))
        {
            throw new SdJwtException("Issuer claim (iss) is required for replay protection", Primitives.ErrorCode.MissingRequiredClaim);
        }

        var issuer = issElement.GetString();
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new SdJwtException("Issuer claim (iss) cannot be empty", Primitives.ErrorCode.InvalidInput);
        }

        // Extract jti
        if (!claims.TryGetValue("jti", out var jtiElement))
        {
            if (_options.RequireJtiClaim)
            {
                throw new SdJwtException("JWT ID claim (jti) is required when replay protection is enabled", Primitives.ErrorCode.MissingRequiredClaim);
            }
            // jti not required, skip replay check
            return;
        }

        var jti = jtiElement.GetString();
        if (string.IsNullOrWhiteSpace(jti))
        {
            throw new SdJwtException("JWT ID claim (jti) cannot be empty", Primitives.ErrorCode.InvalidInput);
        }

        // Calculate TTL based on exp claim
        var ttl = CalculateTtl(claims);

        // Try to add jti to cache (atomic operation)
        var wasAdded = await _cache.TryAddAsync(issuer, jti, ttl, cancellationToken);

        if (!wasAdded)
        {
            // jti already exists in cache - replay detected
            throw new ReplayAttackException(jti, issuer);
        }
    }

    /// <summary>
    /// Calculates cache TTL based on token expiration and configuration.
    /// </summary>
    private TimeSpan CalculateTtl(Dictionary<string, JsonElement> claims)
    {
        // Try to get exp claim
        if (!claims.TryGetValue("exp", out var expElement))
        {
            // No exp claim - use default TTL
            return _options.DefaultTtl;
        }

        // Parse exp as Unix timestamp
        if (!expElement.TryGetInt64(out var expUnixSeconds))
        {
            // Invalid exp format - use default TTL
            return _options.DefaultTtl;
        }

        var exp = DateTimeOffset.FromUnixTimeSeconds(expUnixSeconds);
        var now = DateTimeOffset.UtcNow;

        // Check if token already expired
        if (exp <= now)
        {
            throw new SdJwtException(
                $"Token has expired. Expiration: {exp:O}, Current time: {now:O}",
                Primitives.ErrorCode.TokenExpired);
        }

        // Calculate TTL with clock skew tolerance
        var ttl = (exp - now) + _options.ClockSkewTolerance;

        // Cap at maximum TTL
        if (ttl > _options.MaximumTtl)
        {
            ttl = _options.MaximumTtl;
        }

        // Ensure minimum TTL to prevent immediate expiration
        if (ttl < TimeSpan.FromSeconds(1))
        {
            ttl = TimeSpan.FromSeconds(1);
        }

        return ttl;
    }
}
