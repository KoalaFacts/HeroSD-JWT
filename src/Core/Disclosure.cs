using System.Text.Json;

namespace HeroSdJwt.Core;

/// <summary>
/// Represents a single disclosure in an SD-JWT.
/// A disclosure can be either:
/// - Object property: [salt, claim_name, claim_value] (3-element array)
/// - Array element: [salt, claim_value] (2-element array)
/// Immutable value type for thread safety.
/// </summary>
public readonly struct Disclosure : IEquatable<Disclosure>
{
    /// <summary>
    /// Gets the cryptographically random salt (128+ bits recommended).
    /// Base64url-encoded string.
    /// </summary>
    public string Salt { get; }

    /// <summary>
    /// Gets the name of the claim being disclosed.
    /// Null for array element disclosures (2-element format).
    /// </summary>
    public string? ClaimName { get; }

    /// <summary>
    /// Gets the value of the claim being disclosed.
    /// Can be any JSON-serializable type.
    /// </summary>
    public JsonElement ClaimValue { get; }

    /// <summary>
    /// Gets a value indicating whether this is an array element disclosure (2-element format).
    /// True for array elements, false for object properties.
    /// </summary>
    public bool IsArrayElement => ClaimName == null;

    /// <summary>
    /// Initializes a new instance of the <see cref="Disclosure"/> struct for an object property (3-element format).
    /// </summary>
    /// <param name="salt">The cryptographic salt (base64url-encoded).</param>
    /// <param name="claimName">The claim name.</param>
    /// <param name="claimValue">The claim value.</param>
    /// <exception cref="ArgumentNullException">Thrown when salt or claimName is null.</exception>
    /// <exception cref="ArgumentException">Thrown when salt or claimName is empty or whitespace.</exception>
    public Disclosure(string salt, string claimName, JsonElement claimValue)
    {
        ArgumentNullException.ThrowIfNull(salt);
        ArgumentNullException.ThrowIfNull(claimName);

        if (string.IsNullOrWhiteSpace(salt))
        {
            throw new ArgumentException("Salt cannot be empty or whitespace.", nameof(salt));
        }

        if (string.IsNullOrWhiteSpace(claimName))
        {
            throw new ArgumentException("Claim name cannot be empty or whitespace.", nameof(claimName));
        }

        Salt = salt;
        ClaimName = claimName;
        ClaimValue = claimValue;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Disclosure"/> struct for an array element (2-element format).
    /// </summary>
    /// <param name="salt">The cryptographic salt (base64url-encoded).</param>
    /// <param name="claimValue">The claim value.</param>
    /// <exception cref="ArgumentNullException">Thrown when salt is null.</exception>
    /// <exception cref="ArgumentException">Thrown when salt is empty or whitespace.</exception>
    public Disclosure(string salt, JsonElement claimValue)
    {
        ArgumentNullException.ThrowIfNull(salt);

        if (string.IsNullOrWhiteSpace(salt))
        {
            throw new ArgumentException("Salt cannot be empty or whitespace.", nameof(salt));
        }

        Salt = salt;
        ClaimName = null;
        ClaimValue = claimValue;
    }

    /// <summary>
    /// Returns the JSON array representation of this disclosure.
    /// Format: [salt, claim_name, claim_value] for object properties (3-element)
    /// or [salt, claim_value] for array elements (2-element).
    /// </summary>
    /// <returns>JSON string representation.</returns>
    public string ToJson()
    {
        if (IsArrayElement)
        {
            // Array element disclosure: [salt, claim_value]
            return JsonSerializer.Serialize(new object[] { Salt, ClaimValue });
        }
        else
        {
            // Object property disclosure: [salt, claim_name, claim_value]
            return JsonSerializer.Serialize(new object[] { Salt, ClaimName!, ClaimValue });
        }
    }

    /// <inheritdoc/>
    public bool Equals(Disclosure other)
    {
        return Salt == other.Salt &&
               ClaimName == other.ClaimName &&
               ClaimValue.ToString() == other.ClaimValue.ToString();
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is Disclosure other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Salt, ClaimName, ClaimValue.ToString());
    }

    /// <summary>
    /// Determines whether two <see cref="Disclosure"/> instances are equal.
    /// </summary>
    public static bool operator ==(Disclosure left, Disclosure right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two <see cref="Disclosure"/> instances are not equal.
    /// </summary>
    public static bool operator !=(Disclosure left, Disclosure right)
    {
        return !left.Equals(right);
    }

    /// <inheritdoc/>
    public override string ToString()
    {
        if (IsArrayElement)
        {
            return $"Disclosure(Salt={Salt[..Math.Min(8, Salt.Length)]}..., ArrayElement)";
        }
        return $"Disclosure(Salt={Salt[..Math.Min(8, Salt.Length)]}..., ClaimName={ClaimName})";
    }
}
