namespace HeroSdJwt.Verification;

/// <summary>
/// Interface for validating JWT signatures.
/// </summary>
public interface ISignatureValidator
{
    /// <summary>
    /// Verifies the signature of a JWT.
    /// </summary>
    /// <param name="jwt">The JWT in format: header.payload.signature</param>
    /// <param name="publicKey">The public key or shared secret for verification.</param>
    /// <returns>True if signature is valid; otherwise, false.</returns>
    bool VerifyJwtSignature(string jwt, byte[] publicKey);
}
