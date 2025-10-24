using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests;

/// <summary>
/// Factory methods for creating test instances with dependency injection.
/// Provides convenient defaults for testing scenarios.
/// </summary>
public static class TestHelpers
{
    /// <summary>
    /// Creates an SdJwtVerifier with default dependencies for testing.
    /// </summary>
    public static SdJwtVerifier CreateVerifier(SdJwtVerificationOptions? options = null)
    {
        return new SdJwtVerifier(
            options ?? new SdJwtVerificationOptions(),
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(),
            new ClaimValidator());
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
