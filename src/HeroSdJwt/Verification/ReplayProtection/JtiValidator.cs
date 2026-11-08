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
        ArgumentNullException.ThrowIfNull(options);
        // The replay policy controls whether tokens are admitted at all and
        // how long replay markers survive. Keep the validated policy independent
        // from mutable options retained by the caller.
        _options = new ReplayProtectionOptions
        {
            Enabled = options.Enabled,
            FailureMode = options.FailureMode,
            MaxCacheEntries = options.MaxCacheEntries,
            DefaultTtl = options.DefaultTtl,
            MaximumTtl = options.MaximumTtl,
            ClockSkewTolerance = options.ClockSkewTolerance,
            RequireJtiClaim = options.RequireJtiClaim
        };
        // Custom IJtiCache implementations do not necessarily validate replay options.
        // Validate the owned snapshot, not mutable caller state, before accepting tokens.
        _options.Validate();
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <summary>
    /// Validates jti claim and checks for replay attacks.
    /// </summary>
    /// <param name="claims">JWT payload claims.</param>
    /// <param name="cancellationToken">Cancellation token for async operations.</param>
    /// <exception cref="SdJwtException">If jti/exp is missing when required or validation fails.</exception>
    /// <exception cref="ReplayAttackException">If jti has already been used.</exception>
    public Task ValidateAsync(Dictionary<string, JsonElement> claims, CancellationToken cancellationToken = default)
    {
        return ValidateAsync(claims, _options.ClockSkewTolerance, cancellationToken);
    }

    // The signed-claim verifier may accept a presentation beyond raw exp
    // because its clock-skew policy differs from replay cache configuration.
    // Retain the marker until at least the verifier's acceptance deadline.
    internal async Task ValidateAsync(
        Dictionary<string, JsonElement> claims,
        TimeSpan verifierClockSkew,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claims);

        // If replay protection disabled, skip validation
        if (!_options.Enabled)
        {
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();

        // With no canonical jti there is no replay marker to key or retain.
        // Preserve the issuer/expiration requirements whenever jti is present.
        if (!_options.RequireJtiClaim && !TryGetRegisteredClaim(claims, "jti", out _))
        {
            return;
        }

        // Extract issuer (required for cache key)
        if (!TryGetRegisteredClaim(claims, "iss", out var issElement))
        {
            throw new SdJwtException("Issuer claim (iss) is required for replay protection", Primitives.ErrorCode.MissingRequiredClaim);
        }

        if (issElement.ValueKind != JsonValueKind.String)
        {
            throw new SdJwtException("Issuer claim (iss) must be a string", Primitives.ErrorCode.InvalidInput);
        }

        var issuer = GetRegisteredClaimString(issElement, "iss");
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new SdJwtException("Issuer claim (iss) cannot be empty", Primitives.ErrorCode.InvalidInput);
        }

        // Extract jti
        if (!TryGetRegisteredClaim(claims, "jti", out var jtiElement))
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

        var jti = GetRegisteredClaimString(jtiElement, "jti");
        if (string.IsNullOrWhiteSpace(jti))
        {
            throw new SdJwtException("JWT ID claim (jti) cannot be empty", Primitives.ErrorCode.InvalidInput);
        }

        // The replay marker must cover the entire accepted expiration window.
        // Never shorten a live token's marker to a default or maximum TTL.
        var ttl = CalculateTtl(claims, verifierClockSkew);

        // Only the explicitly configured availability-first mode may ignore a
        // storage failure. A canceled operation or a real replay is never an outage.
        bool wasAdded;
        try
        {
            wasAdded = await _cache.TryAddAsync(issuer, jti, ttl, cancellationToken).ConfigureAwait(false);

            // An atomic adapter can finish admission despite caller cancellation.
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ReplayAttackException)
        {
            // An atomic provider's affirmative replay report is not an outage.
            throw;
        }
        catch (InvalidOperationException)
        {
            // A provider reporting invalid state cannot guarantee atomic replay
            // admission, regardless of whether it is the built-in cache or a
            // custom adapter. This is not a transient outage: fail closed even
            // when the caller explicitly selected FailOpen for storage failures.
            throw;
        }
        catch (Exception error) when (
            _options.FailureMode == CacheFailureMode.FailOpen &&
            StorageFailureClassifier.IsTransient(error))
        {
            // Only known transport failures and timeouts may bypass admission.
            // Malformed records or unknown provider failures must fail closed.
            cancellationToken.ThrowIfCancellationRequested();
            return;
        }

        if (!wasAdded)
        {
            // jti already exists in cache - replay detected
            throw new ReplayAttackException(jti, issuer);
        }
    }

    // A parsed JSON string may still carry an escaped lone surrogate.
    // The standalone replay API must reject it with its documented domain error.
    private static string? GetRegisteredClaimString(JsonElement element, string claimName)
    {
        try
        {
            return element.GetString();
        }
        catch (InvalidOperationException)
        {
            throw new SdJwtException(
                $"JWT {claimName} claim contains malformed Unicode",
                Primitives.ErrorCode.InvalidInput);
        }
    }

    // Registered JWT claim names are case-sensitive even when a standalone
    // caller supplies a dictionary with a case-insensitive/custom comparer.
    // Keep O(1) lookups for the normal ordinal dictionaries from verification.
    private static bool TryGetRegisteredClaim(
        Dictionary<string, JsonElement> claims,
        string claimName,
        out JsonElement value)
    {
        if (ReferenceEquals(claims.Comparer, EqualityComparer<string>.Default) ||
            ReferenceEquals(claims.Comparer, StringComparer.Ordinal))
        {
            return claims.TryGetValue(claimName, out value);
        }

        foreach (var (name, candidate) in claims)
        {
            if (string.Equals(name, claimName, StringComparison.Ordinal))
            {
                value = candidate;
                return true;
            }
        }

        value = default;
        return false;
    }

    /// <summary>
    /// Calculates a marker lifetime covering the entire remaining token validity.
    /// Rejects credentials that cannot be protected within the configured retention limit.
    /// </summary>
    private TimeSpan CalculateTtl(Dictionary<string, JsonElement> claims, TimeSpan verifierClockSkew)
    {
        if (!TryGetRegisteredClaim(claims, "exp", out var expElement))
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

        if (_options.ClockSkewTolerance < TimeSpan.Zero || verifierClockSkew < TimeSpan.Zero || _options.MaximumTtl <= TimeSpan.Zero)
        {
            throw new SdJwtException(
                "Invalid replay marker retention configuration",
                Primitives.ErrorCode.InvalidInput);
        }

        // The replay marker must remain live throughout the entire period in
        // which the claim verifier accepts exp. The standalone replay tolerance
        // may be shorter or longer; use the longer window for both safety and
        // interoperability.
        var effectiveSkewTicks = Math.Max(_options.ClockSkewTolerance.Ticks, verifierClockSkew.Ticks);
        var ttlTicks = expUnixTicks - nowUnixTicks + effectiveSkewTicks;
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
        return TimeSpan.FromTicks(roundedTtlTicks);
    }
}
