namespace HeroSdJwt.KeyBinding;

/// <summary>
/// Interface for validating key binding JWTs.
/// </summary>
public interface IKeyBindingValidator
{
    /// <summary>
    /// Validates a key binding JWT against the holder's public key.
    /// </summary>
    /// <param name="keyBindingJwt">The key binding JWT to validate.</param>
    /// <param name="holderPublicKey">The holder's public key from the cnf claim.</param>
    /// <param name="expectedSdJwtHash">The expected SD-JWT hash.</param>
    /// <param name="expectedAudience">The expected audience.</param>
    /// <param name="expectedNonce">The expected nonce.</param>
    /// <returns>True if valid; otherwise, false.</returns>
    bool ValidateKeyBinding(
        string keyBindingJwt,
        byte[] holderPublicKey,
        string expectedSdJwtHash,
        string? expectedAudience = null,
        string? expectedNonce = null);
}
