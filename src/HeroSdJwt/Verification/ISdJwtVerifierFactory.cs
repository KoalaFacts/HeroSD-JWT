namespace HeroSdJwt.Verification;

/// <summary>
/// Creates a verifier that enforces a supplied verification policy without changing the source verifier.
/// </summary>
/// <remarks>
/// Authentication integrations require this explicit capability from custom verifiers so that
/// authentication scheme options cannot be silently ignored. Implementations must apply the complete
/// supplied policy and preserve the lifetime and security behavior of their configured dependencies.
/// </remarks>
public interface ISdJwtVerifierFactory
{
    /// <summary>
    /// Creates a verifier for the supplied policy, retaining configured verification dependencies.
    /// </summary>
    /// <param name="options">The complete policy to enforce.</param>
    /// <returns>A verifier isolated from other policies.</returns>
    ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions options);
}
