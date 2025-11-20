using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests;

/// <summary>
/// Factory methods for creating test instances with dependency injection.
/// Provides convenient defaults for testing scenarios.
/// </summary>
internal static class TestHelpers
{
    /// <summary>
    /// Creates an SdJwtVerifier with default dependencies for testing.
    /// </summary>
    public static SdJwtVerifier CreateVerifier(SdJwtVerificationOptions? options = null)
    {
        return new SdJwtVerifier(
            options ?? new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Either },
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(TimeProvider.System),
            new ClaimValidator());
    }

    /// <summary>
    /// Creates an SdJwtVerifier with revocation support for testing.
    /// </summary>
    public static SdJwtVerifier CreateVerifierWithRevocation(
        SdJwtVerificationOptions? options = null,
        IRevocationStore? revocationStore = null)
    {
        return new SdJwtVerifier(
            options ?? new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Either },
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(TimeProvider.System),
            new ClaimValidator(),
            jtiValidator: null,
            revocationStore: revocationStore);
    }

    /// <summary>
    /// Creates a new SdJwtVerifierBuilder for fluent configuration.
    /// Recommended for new code - provides a cleaner, more discoverable API.
    /// </summary>
    /// <example>
    /// <code>
    /// var verifier = TestHelpers.CreateVerifierBuilder()
    ///     .WithRevocation(store)
    ///     .WithExpectedIssuer("https://issuer.example.com")
    ///     .Build();
    /// </code>
    /// </example>
    public static SdJwtVerifierBuilder CreateVerifierBuilder()
    {
        return SdJwtVerifierBuilder.Create();
    }

    /// <summary>
    /// Creates an SdJwtIssuer with default dependencies for testing.
    /// </summary>
    public static SdJwtIssuer CreateIssuer()
    {
        return new SdJwtIssuer(
            new DisclosureGenerator(),
            new DigestCalculator(),
            new EcPublicKeyConverter(),
            new JwtSigner());
    }

    /// <summary>
    /// Creates a DecoyDigestGenerator with default dependencies for testing.
    /// </summary>
    public static DecoyDigestGenerator CreateDecoyGenerator()
    {
        return new DecoyDigestGenerator(new DigestCalculator());
    }
}
