using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Models;

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
            return valueBytes.Length == otherBytes.Length &&
                CryptographicOperations.FixedTimeEquals(valueBytes, otherBytes);
        }
        catch (Exception ex) when (ex is SdJwtException or ArgumentOutOfRangeException)
        {
            // The public constructor accepts malformed Base64Url. A value must
            // still equal itself (and an identical copy). Compare raw UTF-16
            // without an early exit only when decoding cannot succeed.
            return CryptographicOperations.FixedTimeEquals(
                MemoryMarshal.AsBytes(Value.AsSpan()),
                MemoryMarshal.AsBytes(other.Value.AsSpan()));
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
        if (Value is null)
        {
            return HashCode.Combine(Value, Algorithm);
        }

        try
        {
            // Equals compares decoded bytes, not encoded spelling. Padded and
            // unpadded forms must therefore have the same hash for collections.
            var bytes = Base64UrlEncoder.DecodeBytes(Value);
            var hash = new HashCode();
            hash.Add(Algorithm);
            foreach (var valueByte in bytes)
            {
                hash.Add(valueByte);
            }

            return hash.ToHashCode();
        }
        catch (Exception ex) when (ex is SdJwtException or ArgumentOutOfRangeException)
        {
            // Malformed values use raw-content equality and hashing.
            return HashCode.Combine(Value, Algorithm);
        }
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
