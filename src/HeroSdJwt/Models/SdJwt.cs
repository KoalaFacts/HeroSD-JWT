using System.Collections.ObjectModel;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Models;

/// <summary>
/// Represents a complete SD-JWT (Selective Disclosure JSON Web Token).
/// Contains the JWT, associated disclosures, and metadata.
/// </summary>
public sealed class SdJwt
{
    /// <summary>
    /// Gets the JWT portion (header + payload + signature).
    /// This is the base JWT containing digests in the '_sd' array.
    /// </summary>
    public string Jwt { get; }

    /// <summary>
    /// Gets the list of disclosures associated with this SD-JWT.
    /// Each disclosure is base64url-encoded.
    /// </summary>
    public IReadOnlyList<string> Disclosures { get; }

    /// <summary>
    /// Gets the hash algorithm used for computing disclosure digests.
    /// Specified in the JWT payload as '_sd_alg'.
    /// </summary>
    public HashAlgorithm HashAlgorithm { get; }

    /// <summary>
    /// Gets the optional key binding JWT.
    /// Present only when key binding is required.
    /// </summary>
    public string? KeyBindingJwt { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwt"/> class.
    /// </summary>
    /// <param name="jwt">The base JWT string.</param>
    /// <param name="disclosures">The list of base64url-encoded disclosures.</param>
    /// <param name="hashAlgorithm">The hash algorithm used.</param>
    /// <param name="keyBindingJwt">Optional key binding JWT.</param>
    /// <exception cref="ArgumentNullException">Thrown when jwt or disclosures is null.</exception>
    /// <exception cref="ArgumentException">Thrown when jwt is empty or whitespace.</exception>
    public SdJwt(string jwt, IEnumerable<string> disclosures, HashAlgorithm hashAlgorithm, string? keyBindingJwt = null)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(disclosures);

        if (string.IsNullOrWhiteSpace(jwt))
        {
            throw new ArgumentException("JWT cannot be empty or whitespace.", nameof(jwt));
        }

        Jwt = jwt;
        Disclosures = new ReadOnlyCollection<string>(disclosures.ToList());
        HashAlgorithm = hashAlgorithm;
        KeyBindingJwt = keyBindingJwt;
    }

    /// <summary>
    /// Returns the combined presentation format.
    /// Format: {JWT}~{disclosure1}~{disclosure2}~...~{keyBindingJwt}
    /// </summary>
    /// <returns>The combined SD-JWT presentation string.</returns>
    public string ToCombinedFormat()
    {
        var parts = new List<string> { Jwt };
        parts.AddRange(Disclosures);

        if (!string.IsNullOrEmpty(KeyBindingJwt))
        {
            parts.Add(KeyBindingJwt);
        }
        else
        {
            // Add empty string for key binding JWT if not present
            parts.Add(string.Empty);
        }

        return string.Join("~", parts);
    }

    /// <summary>
    /// Returns a string representation of this SD-JWT.
    /// </summary>
    public override string ToString()
    {
        var kbStatus = KeyBindingJwt != null ? "with KB" : "no KB";
        return $"SdJwt(Disclosures={Disclosures.Count}, HashAlgorithm={HashAlgorithm}, {kbStatus})";
    }
}
