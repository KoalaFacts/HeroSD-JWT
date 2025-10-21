using HeroSdJwt.Common;
using HeroSdJwt.Core;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

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
    private Dictionary<string, object>? _claims;
    private List<string> _selectiveClaims = new();
    private byte[]? _signingKey;
    private HashAlgorithm _hashAlgorithm = HashAlgorithm.Sha256;
    private SignatureAlgorithm _signatureAlgorithm = SignatureAlgorithm.HS256;
    private byte[]? _holderPublicKey;
    private int _decoyDigestCount = 0;

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
        _claims = claims ?? throw new ArgumentNullException(nameof(claims));
        return this;
    }

    /// <summary>
    /// Adds a single claim to the SD-JWT.
    /// </summary>
    /// <param name="name">Claim name.</param>
    /// <param name="value">Claim value.</param>
    public SdJwtBuilder WithClaim(string name, object value)
    {
        _claims ??= new Dictionary<string, object>();
        _claims[name] = value;
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
        _selectiveClaims.AddRange(claimNames);
        return this;
    }

    /// <summary>
    /// Signs the SD-JWT with HMAC-SHA256.
    /// This is the most common and simplest signature algorithm.
    /// </summary>
    /// <param name="key">HMAC key (recommended: 256 bits / 32 bytes).</param>
    public SdJwtBuilder SignWithHmac(byte[] key)
    {
        _signingKey = key ?? throw new ArgumentNullException(nameof(key));
        _signatureAlgorithm = SignatureAlgorithm.HS256;
        return this;
    }

    /// <summary>
    /// Signs the SD-JWT with RSA-SHA256.
    /// Requires a private key in PKCS#8 format (minimum 2048 bits).
    /// </summary>
    /// <param name="privateKey">RSA private key in PKCS#8 format.</param>
    public SdJwtBuilder SignWithRsa(byte[] privateKey)
    {
        _signingKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        _signatureAlgorithm = SignatureAlgorithm.RS256;
        return this;
    }

    /// <summary>
    /// Signs the SD-JWT with ECDSA P-256 SHA256.
    /// Requires a private key in PKCS#8 format with P-256 curve.
    /// </summary>
    /// <param name="privateKey">ECDSA private key in PKCS#8 format.</param>
    public SdJwtBuilder SignWithEcdsa(byte[] privateKey)
    {
        _signingKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        _signatureAlgorithm = SignatureAlgorithm.ES256;
        return this;
    }

    /// <summary>
    /// Sets the hash algorithm for disclosure digests.
    /// Default is SHA-256, which is recommended by the SD-JWT specification.
    /// </summary>
    /// <param name="algorithm">Hash algorithm to use.</param>
    public SdJwtBuilder WithHashAlgorithm(HashAlgorithm algorithm)
    {
        _hashAlgorithm = algorithm;
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
        _holderPublicKey = holderPublicKey ?? throw new ArgumentNullException(nameof(holderPublicKey));
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

        _decoyDigestCount = count;
        return this;
    }

    /// <summary>
    /// Builds the SD-JWT with the configured options.
    /// </summary>
    /// <returns>The created SD-JWT.</returns>
    /// <exception cref="InvalidOperationException">Thrown when required properties are not set.</exception>
    public SdJwt Build()
    {
        if (_claims == null)
            throw new InvalidOperationException("Claims must be set. Call WithClaims() or WithClaim().");

        if (_signingKey == null)
            throw new InvalidOperationException("Signing key must be set. Call SignWithHmac(), SignWithRsa(), or SignWithEcdsa().");

        var issuer = new SdJwtIssuer();
        return issuer.CreateSdJwt(
            _claims,
            _selectiveClaims,
            _signingKey,
            _hashAlgorithm,
            _signatureAlgorithm,
            _holderPublicKey,
            _decoyDigestCount);
    }
}
