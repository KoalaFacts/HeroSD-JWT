using HeroSdJwt.Common;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Core;

/// <summary>
/// Represents a cryptographic digest of a disclosure.
/// The digest is computed as Base64url(Hash(Base64url(JSON([salt, claim_name, claim_value])))).
/// Immutable value type for thread safety.
/// </summary>
public readonly struct Digest : IEquatable<Digest>
{
    /// <summary>
    /// Gets the base64url-encoded digest value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Gets the hash algorithm used to compute this digest.
    /// </summary>
    public HashAlgorithm Algorithm { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Digest"/> struct.
    /// </summary>
    /// <param name="value">The base64url-encoded digest value.</param>
    /// <param name="algorithm">The hash algorithm used.</param>
    /// <exception cref="ArgumentNullException">Thrown when value is null.</exception>
    /// <exception cref="ArgumentException">Thrown when value is empty or whitespace.</exception>
    public Digest(string value, HashAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Digest value cannot be empty or whitespace.", nameof(value));
        }

        Value = value;
        Algorithm = algorithm;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Uses constant-time comparison for digest values to prevent timing attacks.
    /// </remarks>
    public bool Equals(Digest other)
    {
        // First check algorithm (not timing-sensitive)
        if (Algorithm != other.Algorithm)
        {
            return false;
        }

        // Handle null cases (structs initialized with default values)
        if (Value == null || other.Value == null)
        {
            return Value == other.Value;
        }

        // Use constant-time comparison for digest values to prevent timing attacks
        try
        {
            var valueBytes = Base64UrlEncoder.DecodeBytes(Value);
            var otherBytes = Base64UrlEncoder.DecodeBytes(other.Value);

            // CryptographicOperations.FixedTimeEquals requires same length
            if (valueBytes.Length != otherBytes.Length)
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(valueBytes, otherBytes);
        }
        catch
        {
            // If decoding fails, this indicates malformed digest values
            // We must fail safely and return false to maintain security
            // Never fall back to non-constant-time comparison as it defeats timing attack prevention
            return false;
        }
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is Digest other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Value, Algorithm);
    }

    /// <summary>
    /// Determines whether two <see cref="Digest"/> instances are equal.
    /// </summary>
    public static bool operator ==(Digest left, Digest right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two <see cref="Digest"/> instances are not equal.
    /// </summary>
    public static bool operator !=(Digest left, Digest right)
    {
        return !left.Equals(right);
    }

    /// <inheritdoc/>
    public override string ToString()
    {
        return $"Digest(Algorithm={Algorithm}, Value={Value[..Math.Min(16, Value.Length)]}...)";
    }
}
