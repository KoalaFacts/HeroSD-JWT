using HeroSdJwt.Cryptography;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification.Revocation;
using HeroSdJwt.Verification.ReplayProtection;
using System;

namespace HeroSdJwt.Verification;

/// <summary>
/// Fluent builder for creating SD-JWT verifiers with a clean, easy-to-use API.
/// Provides sensible defaults and a discoverable interface.
/// </summary>
/// <example>
/// <code>
/// // Simple case
/// var verifier = SdJwtVerifierBuilder.Create()
///     .Build();
///
/// // With revocation
/// var verifier = SdJwtVerifierBuilder.Create()
///     .WithRevocation(revocationStore)
///     .WithFailClosed()
///     .Build();
///
/// // Full configuration
/// var verifier = SdJwtVerifierBuilder.Create()
///     .WithExpectedIssuer("https://issuer.example.com")
///     .WithExpectedAudience("https://api.example.com")
///     .WithClockSkew(TimeSpan.FromMinutes(2))
///     .WithRevocation(revocationStore, RevocationFailureMode.FailClosed)
///     .WithReplayProtection(jtiValidator)
///     .RequireKeyBinding()
///     .Build();
/// </code>
/// </example>
public class SdJwtVerifierBuilder
{
    private TimeSpan _clockSkew = TimeSpan.FromMinutes(5);
    private bool _requireKeyBinding = false;
    private string? _expectedIssuer;
    private string? _expectedAudience;
    private HashAlgorithm? _expectedHashAlgorithm;
    private string? _expectedNonce;
    private VerificationKeyType _expectedKeyType = VerificationKeyType.Asymmetric;
    private RevocationFailureMode _revocationFailureMode = RevocationFailureMode.FailClosed;
    private IRevocationStore? _revocationStore;
    private JtiValidator? _jtiValidator;

    // Optional dependency overrides for testing
    private IEcPublicKeyConverter? _ecPublicKeyConverter;
    private ISignatureValidator? _signatureValidator;
    private IDigestValidator? _digestValidator;
    private IKeyBindingValidator? _keyBindingValidator;
    private IClaimValidator? _claimValidator;

    /// <summary>
    /// Creates a new builder instance with default settings.
    /// </summary>
    public static SdJwtVerifierBuilder Create() => new();

    /// <summary>
    /// Sets the maximum allowed clock skew for temporal claim validation.
    /// Default is 5 minutes.
    /// </summary>
    /// <param name="clockSkew">Clock skew duration (0-5 minutes).</param>
    public SdJwtVerifierBuilder WithClockSkew(TimeSpan clockSkew)
    {
        _clockSkew = clockSkew;
        return this;
    }

    /// <summary>
    /// Requires key binding JWT for all presentations.
    /// When enabled, presentations without key binding will fail verification.
    /// Default is false (key binding is optional).
    /// </summary>
    public SdJwtVerifierBuilder RequireKeyBinding()
    {
        _requireKeyBinding = true;
        return this;
    }

    /// <summary>
    /// Sets the expected issuer (iss claim).
    /// When set, presentations with different issuer will fail verification.
    /// </summary>
    /// <param name="issuer">Expected issuer URI.</param>
    public SdJwtVerifierBuilder WithExpectedIssuer(string issuer)
    {
        _expectedIssuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        return this;
    }

    /// <summary>
    /// Sets the expected audience (aud claim).
    /// When set, presentations without this audience will fail verification.
    /// </summary>
    /// <param name="audience">Expected audience URI.</param>
    public SdJwtVerifierBuilder WithExpectedAudience(string audience)
    {
        _expectedAudience = audience ?? throw new ArgumentNullException(nameof(audience));
        return this;
    }

    /// <summary>
    /// Sets the expected hash algorithm for disclosure digests.
    /// When set, presentations using different hash algorithm will fail verification.
    /// Default is null (any standard algorithm accepted).
    /// </summary>
    /// <param name="algorithm">Expected hash algorithm.</param>
    public SdJwtVerifierBuilder WithExpectedHashAlgorithm(HashAlgorithm algorithm)
    {
        _expectedHashAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the expected verification key type to guard against alg/key-type confusion.
    /// Default is Asymmetric; set to Symmetric for HS* secrets or Either for mixed scenarios.
    /// </summary>
    public SdJwtVerifierBuilder WithExpectedKeyType(VerificationKeyType keyType)
    {
        _expectedKeyType = keyType;
        return this;
    }

    /// <summary>
    /// Sets the expected nonce for key binding JWT validation.
    /// When set, key binding JWTs with different nonce will fail verification.
    /// </summary>
    /// <param name="nonce">Expected nonce value.</param>
    public SdJwtVerifierBuilder WithExpectedNonce(string nonce)
    {
        _expectedNonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        return this;
    }

    /// <summary>
    /// Enables token revocation checking with the specified store.
    /// Revocation checks will validate JTI, Key ID, and User ID revocation.
    /// </summary>
    /// <param name="store">Revocation store implementation.</param>
    /// <param name="failureMode">Failure mode (default: FailClosed).</param>
    public SdJwtVerifierBuilder WithRevocation(
        IRevocationStore store,
        RevocationFailureMode failureMode = RevocationFailureMode.FailClosed)
    {
        _revocationStore = store ?? throw new ArgumentNullException(nameof(store));
        _revocationFailureMode = failureMode;
        return this;
    }

    /// <summary>
    /// Sets revocation failure mode to fail-closed (secure default).
    /// Reject tokens if revocation check fails.
    /// This prioritizes security over availability.
    /// </summary>
    public SdJwtVerifierBuilder WithFailClosed()
    {
        _revocationFailureMode = RevocationFailureMode.FailClosed;
        return this;
    }

    /// <summary>
    /// Sets revocation failure mode to fail-open.
    /// Allow tokens if revocation check fails.
    /// This prioritizes availability over security.
    /// WARNING: Use only if high availability is more important than security.
    /// </summary>
    public SdJwtVerifierBuilder WithFailOpen()
    {
        _revocationFailureMode = RevocationFailureMode.FailOpen;
        return this;
    }

    /// <summary>
    /// Enables replay protection with the specified JTI validator.
    /// Prevents the same token from being verified multiple times.
    /// </summary>
    /// <param name="validator">JTI validator implementation.</param>
    public SdJwtVerifierBuilder WithReplayProtection(JtiValidator validator)
    {
        _jtiValidator = validator ?? throw new ArgumentNullException(nameof(validator));
        return this;
    }

    /// <summary>
    /// Advanced: Sets a custom EC public key converter (for testing).
    /// </summary>
    public SdJwtVerifierBuilder WithEcPublicKeyConverter(IEcPublicKeyConverter converter)
    {
        _ecPublicKeyConverter = converter ?? throw new ArgumentNullException(nameof(converter));
        return this;
    }

    /// <summary>
    /// Advanced: Sets a custom signature validator (for testing).
    /// </summary>
    public SdJwtVerifierBuilder WithSignatureValidator(ISignatureValidator validator)
    {
        _signatureValidator = validator ?? throw new ArgumentNullException(nameof(validator));
        return this;
    }

    /// <summary>
    /// Advanced: Sets a custom digest validator (for testing).
    /// </summary>
    public SdJwtVerifierBuilder WithDigestValidator(IDigestValidator validator)
    {
        _digestValidator = validator ?? throw new ArgumentNullException(nameof(validator));
        return this;
    }

    /// <summary>
    /// Advanced: Sets a custom key binding validator (for testing).
    /// </summary>
    public SdJwtVerifierBuilder WithKeyBindingValidator(IKeyBindingValidator validator)
    {
        _keyBindingValidator = validator ?? throw new ArgumentNullException(nameof(validator));
        return this;
    }

    /// <summary>
    /// Advanced: Sets a custom claim validator (for testing).
    /// </summary>
    public SdJwtVerifierBuilder WithClaimValidator(IClaimValidator validator)
    {
        _claimValidator = validator ?? throw new ArgumentNullException(nameof(validator));
        return this;
    }

    /// <summary>
    /// Builds the SD-JWT verifier with the configured settings.
    /// </summary>
    /// <returns>Configured SD-JWT verifier instance.</returns>
    /// <exception cref="ArgumentException">Thrown when configuration is invalid.</exception>
    public SdJwtVerifier Build()
    {
        // Build verification options
        var options = new SdJwtVerificationOptions
        {
            ClockSkew = _clockSkew,
            RequireKeyBinding = _requireKeyBinding,
            ExpectedIssuer = _expectedIssuer,
            ExpectedAudience = _expectedAudience,
            ExpectedHashAlgorithm = _expectedHashAlgorithm,
            ExpectedNonce = _expectedNonce,
            ExpectedKeyType = _expectedKeyType,
            Revocation = new RevocationOptions
            {
                FailureMode = _revocationFailureMode
            }
        };

        // Validate options
        options.Validate();

        // Create verifier with dependencies (use defaults if not overridden)
        return new SdJwtVerifier(
            options,
            _ecPublicKeyConverter ?? new EcPublicKeyConverter(),
            _signatureValidator ?? new SignatureValidator(),
            _digestValidator ?? new DigestValidator(),
            _keyBindingValidator ?? new KeyBindingValidator(TimeProvider.System),
            _claimValidator ?? new ClaimValidator(),
            _jtiValidator,
            _revocationStore);
    }
}
