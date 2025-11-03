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
    public SdJwtPresentation(string jwt, IEnumerable<string> selectedDisclosures, string? keyBindingJwt = null)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(selectedDisclosures);

        Jwt = jwt;
        SelectedDisclosures = new ReadOnlyCollection<string>(selectedDisclosures.ToList());
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
