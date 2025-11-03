namespace HeroSdJwt.KeyBinding;

/// <summary>
/// Interface for generating key binding JWTs.
/// </summary>
public interface IKeyBindingGenerator
{
    /// <summary>
    /// Creates a key binding JWT signed with the holder's private key.
    /// </summary>
    /// <param name="holderPrivateKey">The holder's ECDSA private key (P-256).</param>
    /// <param name="sdJwtHash">The hash of the SD-JWT being presented.</param>
    /// <param name="audience">The intended audience (verifier).</param>
    /// <param name="nonce">A nonce for replay protection.</param>
    /// <returns>The key binding JWT string.</returns>
    string CreateKeyBindingJwt(
        byte[] holderPrivateKey,
        string sdJwtHash,
        string audience,
        string nonce);
}
