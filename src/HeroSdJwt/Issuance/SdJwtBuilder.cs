using System.Security.Cryptography;
using HeroSdJwt.Models;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;
using SignatureAlgorithm = HeroSdJwt.Primitives.SignatureAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Fluent builder for creating SD-JWTs with a clean, easy-to-use API.
/// Provides sensible defaults and a discoverable interface.
/// </summary>
/// <example>
/// <code>
/// // Simple case with HMAC
/// var sdJwt = SdJwtBuilder.Create()
///     .WithClaims(claims)
///     .MakeSelective("email", "age")
///     .SignWithHmac(key)
///     .Build();
///
/// // With RSA and key binding
/// var sdJwt = SdJwtBuilder.Create()
///     .WithClaims(claims)
///     .MakeSelective("email", "age")
///     .SignWithRsa(privateKey)
///     .WithKeyBinding(holderPublicKey)
///     .WithDecoys(5)
///     .Build();
/// </code>
/// </example>
public class SdJwtBuilder
{
    private Dictionary<string, object>? claims;
    private readonly List<string> selectiveClaims = [];
    private byte[]? signingKey;
    private HashAlgorithm hashAlgorithm = HashAlgorithm.Sha256;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    private byte[]? holderPublicKey;
    private int decoyDigestCount = 0;
    private string? keyId;

    /// <summary>
    /// Creates a new builder instance.
    /// </summary>
    public static SdJwtBuilder Create() => new();

    /// <summary>
    /// Sets all claims for the SD-JWT.
    /// </summary>
    /// <param name="claims">The claims to include in the JWT.</param>
    public SdJwtBuilder WithClaims(Dictionary<string, object> claims)
    {
        this.claims = claims ?? throw new ArgumentNullException(nameof(claims));
        return this;
    }

    /// <summary>
    /// Adds a single claim to the SD-JWT.
    /// </summary>
    /// <param name="name">Claim name.</param>
    /// <param name="value">Claim value.</param>
    public SdJwtBuilder WithClaim(string name, object value)
    {
        claims ??= [];
        claims[name] = value;
        return this;
    }

    /// <summary>
    /// Marks claims as selectively disclosable.
    /// Supports dot notation for nested claims (e.g., "address.city") and
    /// array element notation (e.g., "degrees[1]").
    /// </summary>
    /// <param name="claimNames">Names of claims to make selectively disclosable.</param>
    public SdJwtBuilder MakeSelective(params string[] claimNames)
    {
        selectiveClaims.AddRange(claimNames);
        return this;
    }

    /// <summary>
    /// Signs the SD-JWT with HMAC-SHA256.
    /// This is the most common and simplest signature algorithm.
    /// </summary>
    /// <param name="key">HMAC key (recommended: 256 bits / 32 bytes).</param>
    public SdJwtBuilder SignWithHmac(byte[] key)
    {
        signingKey = key ?? throw new ArgumentNullException(nameof(key));
        signatureAlgorithm = SignatureAlgorithm.HS256;
        return this;
    }

    /// <summary>
    /// Signs the SD-JWT with RSA-SHA256.
    /// Requires a private key in PKCS#8 format (minimum 2048 bits).
    /// </summary>
    /// <param name="privateKey">RSA private key in PKCS#8 format.</param>
    public SdJwtBuilder SignWithRsa(byte[] privateKey)
    {
        signingKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        signatureAlgorithm = SignatureAlgorithm.RS256;
        return this;
    }

    /// <summary>
    /// Signs the SD-JWT with ECDSA P-256 SHA256.
    /// Requires a private key in PKCS#8 format with P-256 curve.
    /// </summary>
    /// <param name="privateKey">ECDSA private key in PKCS#8 format.</param>
    public SdJwtBuilder SignWithEcdsa(byte[] privateKey)
    {
        signingKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        signatureAlgorithm = SignatureAlgorithm.ES256;
        return this;
    }

    /// <summary>
    /// Sets the hash algorithm for disclosure digests.
    /// Default is SHA-256, which is recommended by the SD-JWT specification.
    /// </summary>
    /// <param name="algorithm">Hash algorithm to use.</param>
    public SdJwtBuilder WithHashAlgorithm(HashAlgorithm algorithm)
    {
        hashAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Adds key binding (holder binding) to the SD-JWT.
    /// The holder's public key will be embedded in the JWT's cnf claim,
    /// allowing the holder to prove possession during presentation.
    /// </summary>
    /// <param name="holderPublicKey">Holder's public key in SubjectPublicKeyInfo format.</param>
    public SdJwtBuilder WithKeyBinding(byte[] holderPublicKey)
    {
        this.holderPublicKey = holderPublicKey ?? throw new ArgumentNullException(nameof(holderPublicKey));
        return this;
    }

    /// <summary>
    /// Adds decoy digests for privacy enhancement.
    /// Decoy digests prevent enumeration of the number of selectively disclosable claims.
    /// Per SD-JWT spec section 4.2.5.
    /// </summary>
    /// <param name="count">Number of decoy digests to add (0-50 recommended).</param>
    public SdJwtBuilder WithDecoys(int count)
    {
        if (count < 0)
            throw new ArgumentOutOfRangeException(nameof(count), "Decoy count cannot be negative");

        decoyDigestCount = count;
        return this;
    }

    /// <summary>
    /// Sets the key identifier (kid) to include in the JWT header.
    /// Enables key rotation by identifying which key was used to sign the JWT.
    /// Per RFC 7515 Section 4.1.4.
    /// </summary>
    /// <param name="keyId">The key identifier string (1-256 printable ASCII characters).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when keyId is empty, exceeds 256 characters, or contains non-printable characters.</exception>
    public SdJwtBuilder WithKeyId(string keyId)
    {
        Primitives.KeyIdValidator.Validate(keyId);
        this.keyId = keyId;
        return this;
    }

    /// <summary>
    /// Builds the SD-JWT with the configured options.
    /// </summary>
    /// <returns>The created SD-JWT.</returns>
    /// <exception cref="InvalidOperationException">Thrown when required properties are not set.</exception>
    public SdJwt Build()
    {
        if (claims == null)
            throw new InvalidOperationException("Claims must be set. Call WithClaims() or WithClaim().");

        if (signingKey == null)
            throw new InvalidOperationException("Signing key must be set. Call SignWithHmac(), SignWithRsa(), or SignWithEcdsa().");

        var issuer = new SdJwtIssuer();
        return issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            signingKey,
            hashAlgorithm,
            signatureAlgorithm,
            holderPublicKey,
            decoyDigestCount,
            keyId);
    }
}
