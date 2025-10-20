using HeroSdJwt.Core;

namespace HeroSdJwt.Presentation;

/// <summary>
/// Creates presentations from SD-JWTs by selecting which claims to disclose.
/// </summary>
public class SdJwtPresenter
{
    /// <summary>
    /// Creates a presentation with the specified selected claims.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT to present.</param>
    /// <param name="selectedClaimNames">The names of claims to disclose.</param>
    /// <param name="keyBindingJwt">Optional key binding JWT to prove holder possession of private key.</param>
    /// <returns>The presentation containing only selected disclosures.</returns>
    public SdJwtPresentation CreatePresentation(
        SdJwt sdJwt,
        IEnumerable<string> selectedClaimNames,
        string? keyBindingJwt = null)
    {
        ArgumentNullException.ThrowIfNull(sdJwt);
        ArgumentNullException.ThrowIfNull(selectedClaimNames);

        var selectedClaimsList = selectedClaimNames.ToList();

        // Build a map of claim names to their disclosures
        // Note: Array element disclosures (which have no claim name) are not included in this map
        var claimToDisclosure = new Dictionary<string, string>();
        foreach (var disclosure in sdJwt.Disclosures)
        {
            var claimName = DisclosureParser.GetClaimName(disclosure);
            if (claimName != null)
            {
                claimToDisclosure[claimName] = disclosure;
            }
        }

        // Filter disclosures based on selected claims
        var selectedDisclosures = new List<string>();
        foreach (var claimName in selectedClaimsList)
        {
            if (!claimToDisclosure.TryGetValue(claimName, out var disclosure))
            {
                throw new ArgumentException(
                    $"Claim '{claimName}' not found in SD-JWT disclosures. " +
                    $"Available claims: {string.Join(", ", claimToDisclosure.Keys)}",
                    nameof(selectedClaimNames));
            }

            selectedDisclosures.Add(disclosure);
        }

        // Use provided key binding JWT, or fall back to the one in sdJwt
        var finalKeyBindingJwt = keyBindingJwt ?? sdJwt.KeyBindingJwt;
        return new SdJwtPresentation(sdJwt.Jwt, selectedDisclosures, finalKeyBindingJwt);
    }

    /// <summary>
    /// Creates a presentation with all disclosures included.
    /// Convenience method for full disclosure.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT to present.</param>
    /// <param name="keyBindingJwt">Optional key binding JWT to prove holder possession of private key.</param>
    /// <returns>The presentation containing all disclosures.</returns>
    public SdJwtPresentation CreatePresentationWithAllClaims(SdJwt sdJwt, string? keyBindingJwt = null)
    {
        ArgumentNullException.ThrowIfNull(sdJwt);

        // Use provided key binding JWT, or fall back to the one in sdJwt
        var finalKeyBindingJwt = keyBindingJwt ?? sdJwt.KeyBindingJwt;
        return new SdJwtPresentation(sdJwt.Jwt, sdJwt.Disclosures, finalKeyBindingJwt);
    }

    /// <summary>
    /// Formats a presentation as a tilde-separated string.
    /// Format: {JWT}~{disclosure1}~{disclosure2}~...~{keyBindingJwt}
    /// </summary>
    /// <param name="presentation">The presentation to format.</param>
    /// <returns>The formatted presentation string.</returns>
    public string FormatPresentation(SdJwtPresentation presentation)
    {
        ArgumentNullException.ThrowIfNull(presentation);

        // Build the combined format: JWT~disclosure1~disclosure2~...~keyBinding
        // Start with JWT
        var parts = new List<string> { presentation.Jwt };

        // Add all disclosures (or empty slot if none)
        if (presentation.SelectedDisclosures.Count > 0)
        {
            parts.AddRange(presentation.SelectedDisclosures);
        }
        else
        {
            // Add empty disclosure slot when no disclosures
            parts.Add(string.Empty);
        }

        // Add key binding (or empty string if not present)
        parts.Add(presentation.KeyBindingJwt ?? string.Empty);

        return string.Join(Constants.CombinedFormatSeparator, parts);
    }
}

