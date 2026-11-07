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
    /// <exception cref="ArgumentException">The presentation exceeds the wire-size or disclosure-count limit.</exception>
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

        // A lazy disclosure source may exceed the wire budget long before it
        // reaches the 100-slot limit. Track the combined size as it is read so
        // an impossible presentation never drains the remainder of the source.
        // Match FormatPresentation's fast UTF-16 bound and exact UTF-8 check.
        long combinedCharacterLength = (long)jwt.Length + 1 + (keyBindingJwt?.Length ?? 0);
        long combinedUtf8Length = 0;
        var measuringUtf8 = false;
        var ownedDisclosures = new List<string>();
        foreach (var disclosure in selectedDisclosures)
        {
            if (ownedDisclosures.Count >= Constants.MAX_DISCLOSURES)
            {
                throw new ArgumentException(
                    $"Presentation exceeds the maximum of {Constants.MAX_DISCLOSURES} disclosures.",
                    nameof(selectedDisclosures));
            }

            combinedCharacterLength += (disclosure?.Length ?? 0) + 1;
            if (combinedCharacterLength > Constants.MAX_JWT_SIZE_BYTES)
            {
                throw new ArgumentException(
                    "Selected disclosures exceed the maximum combined presentation size.",
                    nameof(selectedDisclosures));
            }

            // Only measure UTF-8 when even the three-byte-per-code-unit
            // bound could overflow. Scan previously accepted values once,
            // then account for each following disclosure incrementally.
            if (!measuringUtf8 && combinedCharacterLength > Constants.MAX_JWT_SIZE_BYTES / 3)
            {
                measuringUtf8 = true;
                combinedUtf8Length = (long)System.Text.Encoding.UTF8.GetByteCount(jwt) + 1 +
                    System.Text.Encoding.UTF8.GetByteCount(keyBindingJwt ?? string.Empty);
                foreach (var previous in ownedDisclosures)
                {
                    combinedUtf8Length += System.Text.Encoding.UTF8.GetByteCount(previous ?? string.Empty) + 1;
                }
            }

            if (measuringUtf8)
            {
                combinedUtf8Length += System.Text.Encoding.UTF8.GetByteCount(disclosure ?? string.Empty) + 1;
                if (combinedUtf8Length > Constants.MAX_JWT_SIZE_BYTES)
                {
                    throw new ArgumentException(
                        "Selected disclosures exceed the maximum combined presentation byte size.",
                        nameof(selectedDisclosures));
                }
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
