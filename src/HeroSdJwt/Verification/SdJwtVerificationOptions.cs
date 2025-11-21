using HeroSdJwt.Primitives;
using HeroSdJwt.Verification.Revocation;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;
using System.Collections.Generic;
using System.Linq;

namespace HeroSdJwt.Verification;

/// <summary>
/// Configuration options for SD-JWT presentation verification.
/// This class is immutable after construction to prevent race conditions.
/// </summary>
public class SdJwtVerificationOptions
{
    private IReadOnlyList<string>? _expectedAudiences;

    /// <summary>
    /// Gets the maximum allowed clock skew for temporal claim validation.
    /// Default is 5 minutes (300 seconds).
    /// Valid range: 0-300 seconds per constitution requirements.
    /// </summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets whether key binding JWT is required.
    /// When true, presentations without key binding will fail verification.
    /// Default is false (key binding is optional unless explicitly enabled).
    /// </summary>
    public bool RequireKeyBinding { get; init; } = false;

    /// <summary>
    /// Gets the expected issuer (iss claim).
    /// When set, presentations with different issuer will fail verification.
    /// Default is null (issuer not validated).
    /// </summary>
    public string? ExpectedIssuer { get; init; }

    /// <summary>
    /// Gets the expected audience (aud claim).
    /// When set, presentations without this audience will fail verification.
    /// Default is null (audience not validated).
    /// </summary>
    public string? ExpectedAudience { get; init; }

    /// <summary>
    /// Gets the set of acceptable audiences (aud claim).
    /// When provided, presentations must contain at least one of these audiences.
    /// Default is null/empty (audience not validated).
    /// </summary>
    public IReadOnlyList<string>? ExpectedAudiences
    {
        get => _expectedAudiences;
        init => _expectedAudiences = value?.ToArray();
    }

    /// <summary>
    /// Gets the expected hash algorithm for disclosure digests.
    /// When set, presentations using different hash algorithm will fail verification.
    /// Default is null (any standard algorithm accepted).
    /// </summary>
    public HashAlgorithm? ExpectedHashAlgorithm { get; init; }

    /// <summary>
    /// Gets the expected nonce for key binding JWT validation.
    /// When set, key binding JWTs with different nonce will fail verification.
    /// Default is null (nonce not validated).
    /// </summary>
    public string? ExpectedNonce { get; init; }

    /// <summary>
    /// Gets the expected type of verification key. Defaults to Asymmetric to prevent HS*/SPKI confusion.
    /// Set to Symmetric when verifying HMAC-based tokens, or Either only when both are truly expected.
    /// </summary>
    public VerificationKeyType ExpectedKeyType { get; init; } = VerificationKeyType.Asymmetric;

    /// <summary>
    /// Gets the revocation options for token revocation checking.
    /// Revocation is always enabled when a RevocationStore is provided to the verifier.
    /// </summary>
    public RevocationOptions Revocation { get; init; } = new();

    /// <summary>
    /// Validates the options and throws if configuration is invalid.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when clock skew exceeds maximum allowed value.</exception>
    public void Validate()
    {
        if (ClockSkew < TimeSpan.Zero)
        {
            throw new ArgumentException("Clock skew cannot be negative", nameof(ClockSkew));
        }

        if (ClockSkew > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentException(
                "Clock skew cannot exceed 5 minutes per security requirements",
                nameof(ClockSkew));
        }

        var audiences = GetExpectedAudiences();

        if (RequireKeyBinding)
        {
            if (audiences.Count == 0)
            {
                throw new ArgumentException(
                    "Key binding requires an expected audience value.",
                    nameof(ExpectedAudiences));
            }

            if (string.IsNullOrWhiteSpace(ExpectedNonce))
            {
                throw new ArgumentException(
                    "Key binding requires an expected nonce value.",
                    nameof(ExpectedNonce));
            }
        }
    }

    /// <summary>
    /// Returns the configured expected audiences, normalized and deduplicated.
    /// Combines the singular ExpectedAudience with the plural ExpectedAudiences.
    /// </summary>
    internal IReadOnlyList<string> GetExpectedAudiences()
    {
        var audiences = new List<string>();

        if (!string.IsNullOrWhiteSpace(ExpectedAudience))
        {
            audiences.Add(ExpectedAudience);
        }

        if (_expectedAudiences is { Count: > 0 })
        {
            foreach (var audience in _expectedAudiences)
            {
                if (!string.IsNullOrWhiteSpace(audience))
                {
                    audiences.Add(audience);
                }
            }
        }

        if (audiences.Count == 0)
        {
            return Array.Empty<string>();
        }

        return audiences
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }
}
