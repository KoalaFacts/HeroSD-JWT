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
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Creates a replay validator using the system clock.
    /// </summary>
    /// <param name="cache">Cache that atomically admits replay identifiers.</param>
    /// <param name="options">Replay protection and marker retention options.</param>
    public JtiValidator(IJtiCache cache, ReplayProtectionOptions options)
        : this(cache, options, TimeProvider.System)
    {
    }

    // Keep the existing public constructor. A test clock makes expiry/retention
    // boundaries deterministic without altering the authentication API.
    internal JtiValidator(IJtiCache cache, ReplayProtectionOptions options, TimeProvider timeProvider)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <summary>
    /// Validates jti claim and checks for replay attacks.
    /// </summary>
    /// <param name="claims">JWT payload claims.</param>
    /// <param name="cancellationToken">Cancellation token for async operations.</param>
    /// <exception cref="SdJwtException">If jti/exp is missing when required or validation fails.</exception>
    /// <exception cref="ReplayAttackException">If jti has already been used.</exception>
    public async Task ValidateAsync(Dictionary<string, JsonElement> claims, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claims);

        // If replay protection disabled, skip validation
        if (!_options.Enabled)
        {
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Extract issuer (required for cache key)
        if (!claims.TryGetValue("iss", out var issElement))
        {
            throw new SdJwtException("Issuer claim (iss) is required for replay protection", Primitives.ErrorCode.MissingRequiredClaim);
        }

        if (issElement.ValueKind != JsonValueKind.String)
        {
            throw new SdJwtException("Issuer claim (iss) must be a string", Primitives.ErrorCode.InvalidInput);
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

        if (jtiElement.ValueKind != JsonValueKind.String)
        {
            throw new SdJwtException("JWT ID claim (jti) must be a string", Primitives.ErrorCode.InvalidInput);
        }

        var jti = jtiElement.GetString();
        if (string.IsNullOrWhiteSpace(jti))
        {
            throw new SdJwtException("JWT ID claim (jti) cannot be empty", Primitives.ErrorCode.InvalidInput);
        }

        // The replay marker must cover the entire accepted expiration window.
        // Never shorten a live token's marker to a default or maximum TTL.
        var ttl = CalculateTtl(claims);

        // Try to add jti to cache (atomic operation)
        var wasAdded = await _cache.TryAddAsync(issuer, jti, ttl, cancellationToken).ConfigureAwait(false);

        // Some cache adapters finish an atomic admission despite caller cancellation.
        // Never report that canceled work successfully verified a credential.
        cancellationToken.ThrowIfCancellationRequested();

        if (!wasAdded)
        {
            // jti already exists in cache - replay detected
            throw new ReplayAttackException(jti, issuer);
        }
    }

    /// <summary>
    /// Calculates a marker lifetime covering the entire remaining token validity.
    /// Rejects credentials that cannot be protected within the configured retention limit.
    /// </summary>
    private TimeSpan CalculateTtl(Dictionary<string, JsonElement> claims)
    {
        if (!claims.TryGetValue("exp", out var expElement))
        {
            throw new SdJwtException(
                "Expiration claim (exp) is required for replay protection",
                Primitives.ErrorCode.MissingRequiredClaim);
        }

        // Keep replay protection compatible with the issuer and claim validator:
        // RFC 7519 NumericDate permits fractional seconds and exponent notation.
        // Retain decimal 100-ns precision so sub-tick expiry cannot be rounded
        // down before a replay marker's retention window is determined.
        if (!NumericDateParser.TryParseUnixTicks(expElement, out var expUnixTicks))
        {
            throw new SdJwtException(
                "Expiration claim (exp) must be a valid RFC 7519 NumericDate",
                Primitives.ErrorCode.InvalidInput);
        }

        var now = _timeProvider.GetUtcNow();
        var nowUnixTicks = NumericDateParser.GetCurrentUnixTicks(now);

        if (_options.ClockSkewTolerance < TimeSpan.Zero || _options.MaximumTtl <= TimeSpan.Zero)
        {
            throw new SdJwtException(
                "Invalid replay marker retention configuration",
                Primitives.ErrorCode.InvalidInput);
        }

        // Match the claim verifier's strict exp + skew deadline. A credential
        // accepted shortly after exp still needs replay protection until that
        // same deadline; rejecting at raw exp makes the two policies disagree.
        var ttlTicks = expUnixTicks - nowUnixTicks + _options.ClockSkewTolerance.Ticks;
        if (ttlTicks <= 0)
        {
            throw new SdJwtException(
                $"Token has expired. Expiration: {expElement.GetRawText()}, Current time: {now:O}",
                Primitives.ErrorCode.TokenExpired);
        }

        // Capping TTL would allow a still-valid credential to be admitted again
        // after its marker expires. Reject instead of silently weakening replay protection.
        if (ttlTicks > _options.MaximumTtl.Ticks)
        {
            throw new SdJwtException(
                "Credential expiration exceeds replay marker MaximumTtl; increase MaximumTtl or issue shorter-lived credentials",
                Primitives.ErrorCode.InvalidInput);
        }

        // Cache implementations retain TimeSpan ticks. Always round UP here:
        // truncating a sub-tick NumericDate would expire the marker too early.
        var roundedTtlTicks = (long)decimal.Ceiling(ttlTicks);
        return TimeSpan.FromTicks(Math.Max(TimeSpan.TicksPerSecond, roundedTtlTicks));
    }
}
