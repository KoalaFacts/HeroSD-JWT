using HeroSdJwt.Models;

namespace HeroSdJwt.Presentation;

/// <summary>
/// Creates presentations from SD-JWTs by selecting which claims to disclose.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="SdJwtPresenter"/> class with dependencies.
/// </remarks>
/// <param name="claimPathMapper">The claim path mapper to use.</param>
public class SdJwtPresenter(IDisclosureClaimPathMapper claimPathMapper) : ISdJwtPresenter
{
    private readonly IDisclosureClaimPathMapper _claimPathMapper = claimPathMapper ?? throw new ArgumentNullException(nameof(claimPathMapper));

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtPresenter"/> class.
    /// </summary>
    public SdJwtPresenter()
        : this(new DisclosureClaimPathMapper())
    {
    }

    /// <summary>
    /// Creates a presentation with the specified selected claims.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT to present.</param>
    /// <param name="selectedClaimNames">Claim paths to disclose. An unqualified short name must match exactly one path; ambiguous names require full paths.</param>
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

        try
        {

            // Use cached claim path mapping if available (computed at issuance time for performance),
            // otherwise compute on-demand per SD-JWT spec: "it is up to the Holder how to maintain the mapping"
            IReadOnlyDictionary<string, int> claimPathToIndex = sdJwt.ClaimPathMapping
                ?? _claimPathMapper.BuildClaimPathMapping(sdJwt);

            // Select disclosures based on requested claim paths
            // Also include parent disclosures for nested paths (e.g., for "address.geo.lat", include "address.geo")
            var selectedDisclosureIndices = new HashSet<int>();

            foreach (var requestedPath in selectedClaimsList)
            {
                string claimPath = requestedPath;

                if (!claimPathToIndex.TryGetValue(claimPath, out var disclosureIndex))
                {
                    // Legacy unqualified claim names remain convenient only when unique.
                    // Otherwise choosing the first dictionary entry could disclose
                    // a different claim than the holder intended.
                    string? matchedKey = null;
                    foreach (var kvp in claimPathToIndex)
                    {
                        if (kvp.Key.EndsWith($".{claimPath}", StringComparison.Ordinal) ||
                            kvp.Key.EndsWith($"[{claimPath}]", StringComparison.Ordinal))
                        {
                            if (matchedKey != null)
                            {
                                throw new ArgumentException(
                                    $"Claim path '{claimPath}' is ambiguous. Specify the full claim path.",
                                    nameof(selectedClaimNames));
                            }

                            matchedKey = kvp.Key;
                            disclosureIndex = kvp.Value;
                        }
                    }

                    if (matchedKey == null)
                    {
                        throw new ArgumentException(
                            $"Claim path '{claimPath}' not found in SD-JWT. " +
                            $"Available paths: {string.Join(", ", claimPathToIndex.Keys)}",
                            nameof(selectedClaimNames));
                    }

                    claimPath = matchedKey;
                }

                if (disclosureIndex < 0 || disclosureIndex >= sdJwt.Disclosures.Count)
                {
                    throw new InvalidOperationException(
                        $"Invalid disclosure index {disclosureIndex} for claim '{claimPath}'");
                }

                // Add this disclosure
                _ = selectedDisclosureIndices.Add(disclosureIndex);

                // Disclosures nested below another selectively disclosed value need
                // every available ancestor for the verifier to reconstruct their path.
                // Include object boundaries and array indices; the previous loop skipped
                // the first parent (and all bracket-only boundaries).
                for (int position = 1; position < claimPath.Length; position++)
                {
                    if (claimPath[position] is '.' or '[')
                    {
                        var parentPath = claimPath[..position];
                        if (claimPathToIndex.TryGetValue(parentPath, out var parentIndex))
                        {
                            if (parentIndex < 0 || parentIndex >= sdJwt.Disclosures.Count)
                            {
                                throw new InvalidOperationException(
                                    $"Invalid disclosure index {parentIndex} for claim '{parentPath}'");
                            }

                            _ = selectedDisclosureIndices.Add(parentIndex);
                        }
                    }
                }
            }

            // Convert indices to actual disclosures
            // Sort in-place and build list manually to avoid LINQ allocations
            var indicesArray = new int[selectedDisclosureIndices.Count];
            selectedDisclosureIndices.CopyTo(indicesArray);
            Array.Sort(indicesArray); // Maintain order for consistency

            var selectedDisclosures = new List<string>(indicesArray.Length);
            foreach (var index in indicesArray)
            {
                selectedDisclosures.Add(sdJwt.Disclosures[index]);
            }

            // Use provided key binding JWT, or fall back to the one in sdJwt
            var finalKeyBindingJwt = keyBindingJwt ?? sdJwt.KeyBindingJwt;
            var presentation = new SdJwtPresentation(sdJwt.Jwt, selectedDisclosures, finalKeyBindingJwt);

            return presentation;
        }
        catch
        {
            throw;
        }
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
        // Calculate total length to pre-allocate and avoid List<string> allocation
        const char separator = '~';
        var jwt = presentation.Jwt;
        var disclosures = presentation.SelectedDisclosures;
        var keyBinding = presentation.KeyBindingJwt ?? string.Empty;

        // Calculate total length: JWT + separators + disclosures + keyBinding
        int totalLength = jwt.Length + 1; // JWT + separator
        foreach (var disclosure in disclosures)
        {
            totalLength += disclosure.Length + 1; // disclosure + separator
        }
        totalLength += keyBinding.Length; // final keyBinding (no trailing separator)

        // Build string using string.Create for zero intermediate allocations
        return string.Create(totalLength, (jwt, disclosures, keyBinding), (span, state) =>
        {
            int pos = 0;

            // Write JWT
            state.jwt.AsSpan().CopyTo(span[pos..]);
            pos += state.jwt.Length;
            span[pos++] = separator;

            // Write disclosures
            foreach (var disclosure in state.disclosures)
            {
                disclosure.AsSpan().CopyTo(span[pos..]);
                pos += disclosure.Length;
                span[pos++] = separator;
            }

            // Write key binding
            state.keyBinding.AsSpan().CopyTo(span[pos..]);
        });
    }
}

