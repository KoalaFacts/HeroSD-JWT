using HeroSdJwt.Primitives;
using System.Collections.ObjectModel;

namespace HeroSdJwt.Presentation;

/// <summary>
/// Represents a presentation of an SD-JWT with selected disclosures.
/// </summary>
public sealed class SdJwtPresentation
{
    /// <summary>
    /// Gets the JWT portion of the SD-JWT.
    /// </summary>
    public string Jwt { get; }

    /// <summary>
    /// Gets the selected disclosures to include in this presentation.
    /// </summary>
    public IReadOnlyList<string> SelectedDisclosures { get; }

    /// <summary>
    /// Gets the optional key binding JWT.
    /// </summary>
    public string? KeyBindingJwt { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtPresentation"/> class.
    /// </summary>
    /// <param name="jwt">The JWT string.</param>
    /// <param name="selectedDisclosures">The selected disclosures.</param>
    /// <param name="keyBindingJwt">Optional key binding JWT.</param>
    /// <exception cref="ArgumentException">The minimum presentation exceeds the wire-size limit, or too many disclosures were provided.</exception>
    public SdJwtPresentation(string jwt, IEnumerable<string> selectedDisclosures, string? keyBindingJwt = null)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(selectedDisclosures);

        // A credential may be larger than one wire presentation, but a
        // presentation that cannot fit even without disclosures must be
        // rejected before enumerating a potentially untrusted lazy source.
        if (jwt.Length >= Constants.MAX_JWT_SIZE_BYTES ||
            (jwt.Length >= Constants.MAX_JWT_SIZE_BYTES / 3 &&
             System.Text.Encoding.UTF8.GetByteCount(jwt) >= Constants.MAX_JWT_SIZE_BYTES))
        {
            throw new ArgumentException(
                "JWT is too large to fit in a combined presentation.",
                nameof(jwt));
        }

        if (keyBindingJwt is not null)
        {
            var minimumLength = (long)jwt.Length + 1 + keyBindingJwt.Length;
            if (minimumLength > Constants.MAX_JWT_SIZE_BYTES ||
                (minimumLength > Constants.MAX_JWT_SIZE_BYTES / 3 &&
                 (long)System.Text.Encoding.UTF8.GetByteCount(jwt) + 1 +
                 System.Text.Encoding.UTF8.GetByteCount(keyBindingJwt) > Constants.MAX_JWT_SIZE_BYTES))
            {
                throw new ArgumentException(
                    "JWT and key binding JWT are too large to fit in a combined presentation.",
                    nameof(keyBindingJwt));
            }
        }

        // Stop consuming a lazy source as soon as its count exceeds the same
        // limit enforced by FormatPresentation. Materializing the entire source
        // first could exhaust memory before an invalid presentation is rejected.
        var ownedDisclosures = new List<string>();
        foreach (var disclosure in selectedDisclosures)
        {
            if (ownedDisclosures.Count >= Constants.MAX_DISCLOSURES)
            {
                throw new ArgumentException(
                    $"Presentation exceeds the maximum of {Constants.MAX_DISCLOSURES} disclosures.",
                    nameof(selectedDisclosures));
            }

            ownedDisclosures.Add(disclosure);
        }

        Jwt = jwt;
        SelectedDisclosures = new ReadOnlyCollection<string>(ownedDisclosures);
        KeyBindingJwt = keyBindingJwt;
    }

    /// <summary>
    /// Returns a string representation of this presentation.
    /// </summary>
    public override string ToString()
    {
        var kbStatus = KeyBindingJwt != null ? "with KB" : "no KB";
        return $"SdJwtPresentation(Disclosures={SelectedDisclosures.Count}, {kbStatus})";
    }
}
