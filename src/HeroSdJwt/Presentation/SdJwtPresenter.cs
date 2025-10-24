using HeroSdJwt.Models;
using Constants = HeroSdJwt.Primitives.Constants;

namespace HeroSdJwt.Presentation;

/// <summary>
/// Creates presentations from SD-JWTs by selecting which claims to disclose.
/// </summary>
public class SdJwtPresenter : ISdJwtPresenter
{
    private readonly IDisclosureClaimPathMapper claimPathMapper;

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtPresenter"/> class.
    /// </summary>
    public SdJwtPresenter()
        : this(new DisclosureClaimPathMapper())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtPresenter"/> class with dependencies.
    /// </summary>
    /// <param name="claimPathMapper">The claim path mapper to use.</param>
    public SdJwtPresenter(IDisclosureClaimPathMapper claimPathMapper)
    {
        this.claimPathMapper = claimPathMapper ?? throw new ArgumentNullException(nameof(claimPathMapper));
    }

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

        // Build claim path mapping by analyzing JWT structure
        // This is computed on-demand per SD-JWT spec: "it is up to the Holder how to maintain the mapping"
        var claimPathToIndex = claimPathMapper.BuildClaimPathMapping(sdJwt);

        // Select disclosures based on requested claim paths
        // Also include parent disclosures for nested paths (e.g., for "address.geo.lat", include "address.geo")
        var selectedDisclosureIndices = new HashSet<int>();

        foreach (var requestedPath in selectedClaimsList)
        {
            string claimPath = requestedPath;
            int disclosureIndex;

            if (!claimPathToIndex.TryGetValue(claimPath, out disclosureIndex))
            {
                // Check if this is a simple claim name (legacy support)
                var simpleMatch = claimPathToIndex.FirstOrDefault(kvp =>
                    kvp.Key == claimPath || kvp.Key.EndsWith($".{claimPath}") || kvp.Key.EndsWith($"[{claimPath}]"));

                if (!simpleMatch.Equals(default(KeyValuePair<string, int>)))
                {
                    disclosureIndex = simpleMatch.Value;
                    claimPath = simpleMatch.Key; // Use the full matched path
                }
                else
                {
                    throw new ArgumentException(
                        $"Claim path '{claimPath}' not found in SD-JWT. " +
                        $"Available paths: {string.Join(", ", claimPathToIndex.Keys)}",
                        nameof(selectedClaimNames));
                }
            }

            if (disclosureIndex < 0 || disclosureIndex >= sdJwt.Disclosures.Count)
            {
                throw new InvalidOperationException(
                    $"Invalid disclosure index {disclosureIndex} for claim '{claimPath}'");
            }

            // Add this disclosure
            selectedDisclosureIndices.Add(disclosureIndex);

            // For nested paths, also add all parent disclosures
            // E.g., for "address.geo.lat", also add "address.geo"
            var parts = claimPath.Split('.');
            for (int i = 1; i < parts.Length; i++)
            {
                var parentPath = string.Join(".", parts.Take(i + 1));
                if (claimPathToIndex.TryGetValue(parentPath, out var parentIndex))
                {
                    selectedDisclosureIndices.Add(parentIndex);
                }
            }
        }

        // Convert indices to actual disclosures
        var selectedDisclosures = selectedDisclosureIndices
            .OrderBy(i => i) // Maintain order for consistency
            .Select(i => sdJwt.Disclosures[i])
            .ToList();

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

