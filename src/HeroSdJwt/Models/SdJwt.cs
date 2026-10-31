using System.Collections.ObjectModel;
using HeroSdJwt.Primitives;
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
    /// Gets the cached claim path to disclosure index mapping.
    /// This mapping is computed once during SD-JWT creation to improve presentation performance.
    /// Maps claim paths (e.g., "address.street") to disclosure array indices.
    /// If null, the mapping will be computed on-demand during presentation.
    /// </summary>
    public IReadOnlyDictionary<string, int>? ClaimPathMapping { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwt"/> class.
    /// </summary>
    /// <param name="jwt">The base JWT string.</param>
    /// <param name="disclosures">The list of base64url-encoded disclosures.</param>
    /// <param name="hashAlgorithm">The hash algorithm used.</param>
    /// <param name="keyBindingJwt">Optional key binding JWT.</param>
    /// <param name="claimPathMapping">Optional cached claim path to disclosure index mapping.</param>
    /// <exception cref="ArgumentNullException">Thrown when jwt or disclosures is null.</exception>
    /// <exception cref="ArgumentException">Thrown when jwt is empty or whitespace.</exception>
    public SdJwt(string jwt, IEnumerable<string> disclosures, HashAlgorithm hashAlgorithm, string? keyBindingJwt = null, IReadOnlyDictionary<string, int>? claimPathMapping = null)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(disclosures);

        if (string.IsNullOrWhiteSpace(jwt))
        {
            throw new ArgumentException("JWT cannot be empty or whitespace.", nameof(jwt));
        }

        Jwt = jwt;
        Disclosures = new ReadOnlyCollection<string>([.. disclosures]);
        HashAlgorithm = hashAlgorithm;
        KeyBindingJwt = keyBindingJwt;
        if (claimPathMapping is not null)
        {
            // Keep the cached selection map independent from caller-owned storage.
            // IReadOnlyDictionary does not make an underlying Dictionary immutable.
            var ownedMapping = new Dictionary<string, int>(claimPathMapping.Count, StringComparer.Ordinal);
            foreach (var (path, index) in claimPathMapping)
            {
                ownedMapping.Add(path, index);
            }

            ClaimPathMapping = new ReadOnlyDictionary<string, int>(ownedMapping);
        }
    }

    /// <summary>
    /// Returns the combined presentation format.
    /// Format: {JWT}~{disclosure1}~{disclosure2}~...~{keyBindingJwt}
    /// </summary>
    /// <returns>The combined SD-JWT presentation string.</returns>
    /// <exception cref="ArgumentException">The combined presentation exceeds the verifier's size or disclosure count limit.</exception>
    public string ToCombinedFormat()
    {
        // Issuance and holder serialization must honor the same 64-KiB and
        // 100-disclosure limits as the verifier, rather than emitting a value
        // that cannot pass its admission checks.
        if (Disclosures.Count > Constants.MAX_DISCLOSURES)
        {
            throw new ArgumentException(
                $"Presentation exceeds the maximum of {Constants.MAX_DISCLOSURES} disclosures.");
        }

        long combinedLength = (long)Jwt.Length + 1 + (KeyBindingJwt?.Length ?? 0);
        foreach (var disclosure in Disclosures)
        {
            combinedLength += (disclosure?.Length ?? 0) + 1;
        }

        if (combinedLength > Constants.MAX_JWT_SIZE_BYTES)
        {
            throw new ArgumentException(
                $"Presentation exceeds the maximum allowed size of {Constants.MAX_JWT_SIZE_BYTES} bytes.");
        }

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
