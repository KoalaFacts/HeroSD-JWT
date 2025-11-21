namespace HeroSdJwt.Primitives;

/// <summary>
/// Represents a cryptographic key pair consisting of a private key and a public key.
/// Used for asymmetric cryptography operations including RSA, ECDSA, Ed25519, and post-quantum algorithms.
/// </summary>
public readonly record struct KeyPair
{
    /// <summary>
    /// Gets the private key bytes. Format depends on the algorithm.
    /// </summary>
    public byte[] PrivateKey { get; }

    /// <summary>
    /// Gets the public key bytes. Format depends on the algorithm.
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyPair"/> struct with validation.
    /// </summary>
    /// <param name="privateKey">The private key bytes. Must not be null or empty.</param>
    /// <param name="publicKey">The public key bytes. Must not be null or empty.</param>
    /// <exception cref="ArgumentNullException">Thrown when either key is null.</exception>
    /// <exception cref="ArgumentException">Thrown when either key is empty.</exception>
    public KeyPair(byte[] privateKey, byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(publicKey);

        if (privateKey.Length == 0)
        {
            throw new ArgumentException("Private key cannot be empty", nameof(privateKey));
        }

        if (publicKey.Length == 0)
        {
            throw new ArgumentException("Public key cannot be empty", nameof(publicKey));
        }

        PrivateKey = privateKey;
        PublicKey = publicKey;
    }

    /// <summary>
    /// Deconstructs the key pair into its component keys.
    /// Enables tuple deconstruction syntax: var (privateKey, publicKey) = keyPair;
    /// </summary>
    /// <param name="privateKey">The private key bytes.</param>
    /// <param name="publicKey">The public key bytes.</param>
    public void Deconstruct(out byte[] privateKey, out byte[] publicKey)
    {
        privateKey = PrivateKey;
        publicKey = PublicKey;
    }
}
