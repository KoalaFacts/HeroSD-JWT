using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using System.Text.Json;

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
                    // Only a bare object member name may use the unique-short-name
                    // convenience. A partially qualified path or array selector
                    // must match exactly to avoid revealing another claim.
                    string? matchedKey = null;
                    if (!claimPath.Contains('.') && !claimPath.Contains('[') && !claimPath.Contains(']'))
                    {
                        foreach (var kvp in claimPathToIndex)
                        {
                            // Absolute URI claim names are opaque top-level members,
                            // not nested paths. Never disclose one via short-name fallback.
                            if (kvp.Key.EndsWith($".{claimPath}", StringComparison.Ordinal) &&
                                !Uri.TryCreate(kvp.Key, UriKind.Absolute, out _))
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
                    }

                    if (matchedKey == null)
                    {
                        // Do not enumerate undisclosed claim paths in an exception:
                        // holder API clients and logs may receive this message.
                        throw new ArgumentException(
                            $"Claim path '{claimPath}' not found in SD-JWT.",
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

                // Only a digest reference inside a parent disclosure proves ancestry.
                // Prefix text alone is unsafe: issuers may use literal names such as
                // "profile.email", unrelated to a separately disclosed "profile".
                int childIndex = disclosureIndex;
                var digestCalculator = new DigestCalculator();
                for (int position = claimPath.Length - 1; position >= 1; position--)
                {
                    if (claimPath[position] is '.' or '[')
                    {
                        var parentPath = claimPath[..position];
                        if (!claimPathToIndex.TryGetValue(parentPath, out var parentIndex))
                        {
                            continue;
                        }

                        if (parentIndex < 0 || parentIndex >= sdJwt.Disclosures.Count)
                        {
                            throw new InvalidOperationException(
                                $"Invalid disclosure index {parentIndex} for claim '{parentPath}'");
                        }

                        var childDigest = digestCalculator.ComputeDigest(sdJwt.Disclosures[childIndex], sdJwt.HashAlgorithm);
                        if (ReferencesDigest(sdJwt.Disclosures[parentIndex], childDigest))
                        {
                            _ = selectedDisclosureIndices.Add(parentIndex);
                            childIndex = parentIndex;
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
    /// <exception cref="ArgumentException">The presentation exceeds the verifier's size or disclosure count limit.</exception>
    public string FormatPresentation(SdJwtPresentation presentation)
    {
        ArgumentNullException.ThrowIfNull(presentation);

        // Build the combined format: JWT~disclosure1~disclosure2~...~keyBinding
        // Calculate total length to pre-allocate and avoid List<string> allocation
        const char separator = '~';
        var jwt = presentation.Jwt;
        var disclosures = presentation.SelectedDisclosures;
        var keyBinding = presentation.KeyBindingJwt ?? string.Empty;

        // Match the verifier's existing admission policy before allocating the
        // combined output. It counts both empty slots and disclosed values.
        if (disclosures.Count > Constants.MAX_DISCLOSURES)
        {
            throw new ArgumentException(
                $"Presentation exceeds the maximum of {Constants.MAX_DISCLOSURES} disclosures.",
                nameof(presentation));
        }

        // Use long to prevent an overflowing int length from reaching
        // string.Create, including when a caller supplies very large parts.
        long totalLength = (long)jwt.Length + 1 + keyBinding.Length;
        foreach (var disclosure in disclosures)
        {
            totalLength += disclosure.Length + 1;
        }

        if (totalLength > Constants.MAX_JWT_SIZE_BYTES)
        {
            throw new ArgumentException(
                $"Presentation exceeds the maximum allowed size of {Constants.MAX_JWT_SIZE_BYTES} bytes.",
                nameof(presentation));
        }

        // Build string using string.Create for zero intermediate allocations.
        return string.Create((int)totalLength, (jwt, disclosures, keyBinding), (span, state) =>
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
    // Check only structural SD-JWT digest references, never arbitrary claim text.
    // The parsed document is disposed before returning; no JsonElement escapes.
    private static bool ReferencesDigest(string parentDisclosure, string childDigest)
    {
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeString(parentDisclosure));
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Array || root.GetArrayLength() is not 2 and not 3)
        {
            return false;
        }

        return ContainsDigestReference(root[root.GetArrayLength() - 1], childDigest);
    }

    private static bool ContainsDigestReference(JsonElement element, string digest)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            if (element.TryGetProperty("_sd", out var hashes) && hashes.ValueKind == JsonValueKind.Array)
            {
                foreach (var value in hashes.EnumerateArray())
                {
                    if (value.ValueKind == JsonValueKind.String &&
                        string.Equals(value.GetString(), digest, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }

            foreach (var property in element.EnumerateObject())
            {
                if (property.Name != "_sd" && ContainsDigestReference(property.Value, digest))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object &&
                    item.TryGetProperty("...", out var placeholder) &&
                    item.EnumerateObject().Count() == 1 &&
                    placeholder.ValueKind == JsonValueKind.String &&
                    string.Equals(placeholder.GetString(), digest, StringComparison.Ordinal))
                {
                    return true;
                }

                if (ContainsDigestReference(item, digest))
                {
                    return true;
                }
            }
        }

        return false;
    }

}

