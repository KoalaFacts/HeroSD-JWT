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

        // Stop lazy request streams at the first element beyond the
        // presentation disclosure limit, before resolving any claim paths.
        var selectedClaimsList = new List<string>();
        foreach (var claimName in selectedClaimNames)
        {
            if (selectedClaimsList.Count >= Constants.MAX_DISCLOSURES)
            {
                throw new ArgumentException(
                    $"Presentation exceeds the maximum of {Constants.MAX_DISCLOSURES} claim selectors.",
                    nameof(selectedClaimNames));
            }

            // Reject malformed holder input before performing costly or
            // application-provided claim-path discovery.
            if (string.IsNullOrWhiteSpace(claimName))
            {
                throw new ArgumentException(
                    "Claim selector cannot be null, empty or whitespace.",
                    nameof(selectedClaimNames));
            }

            // A selector larger than the entire allowed presentation can
            // never be valid. Reject it before costly or application-provided
            // path mapping. UTF-8 can use up to 3 bytes per UTF-16 code unit.
            if (claimName.Length > Constants.MAX_JWT_SIZE_BYTES ||
                (claimName.Length > Constants.MAX_JWT_SIZE_BYTES / 3 &&
                 System.Text.Encoding.UTF8.GetByteCount(claimName) > Constants.MAX_JWT_SIZE_BYTES))
            {
                throw new ArgumentException(
                    "Claim selector exceeds the maximum presentation byte size.",
                    nameof(selectedClaimNames));
            }

            // Issuance and disclosure metadata reject unpaired UTF-16 surrogates.
            // Holder selectors must do the same before consulting even a caller-
            // supplied cached mapping. A replacement-character encoding would
            // change the identity of a requested claim path.
            for (var i = 0; i < claimName.Length; i++)
            {
                if (!char.IsSurrogate(claimName[i]))
                {
                    continue;
                }

                if (!char.IsHighSurrogate(claimName[i]) ||
                    i + 1 == claimName.Length ||
                    !char.IsLowSurrogate(claimName[i + 1]))
                {
                    throw new ArgumentException(
                        "Claim selector contains invalid UTF-16.",
                        nameof(selectedClaimNames));
                }

                i++; // The next code unit completes a valid surrogate pair.
            }

            selectedClaimsList.Add(claimName);
        }

        // Revealing no claims needs no claim-path discovery. In particular,
        // imported credentials should not hash and parse every disclosure or
        // invoke application-provided mapping services just to select none.
        if (selectedClaimsList.Count == 0)
        {
            return new SdJwtPresentation(
                sdJwt.Jwt,
                [],
                keyBindingJwt ?? sdJwt.KeyBindingJwt);
        }

        try
        {

            // Use cached claim path mapping if available (computed at issuance time for performance),
            // otherwise compute on-demand per SD-JWT spec: "it is up to the Holder how to maintain the mapping"
            // A public SdJwt constructor can receive an external cached map.
            // Immutability prevents later changes but does not prove the original
            // indices match the issuer's signed digests. An incorrect index could
            // silently expose another claim (e.g. tax_id when selecting email).
            // Issuer-produced maps have already been derived from those digests;
            // keep their fast path without re-parsing each presentation.
            IReadOnlyDictionary<string, int> claimPathToIndex;
            if (sdJwt.ClaimPathMapping is { } issuedMapping && sdJwt.HasTrustedClaimPathMapping)
            {
                claimPathToIndex = issuedMapping;
            }
            else
            {
                claimPathToIndex = _claimPathMapper.BuildClaimPathMapping(sdJwt);
                if (sdJwt.ClaimPathMapping is { } externalMapping)
                {
                    foreach (var (path, index) in externalMapping)
                    {
                        if (!claimPathToIndex.TryGetValue(path, out var actualIndex) ||
                            actualIndex != index)
                        {
                            throw new ArgumentException(
                                "Cached claim path mapping does not match the credential disclosures.",
                                nameof(sdJwt));
                        }
                    }
                }
            }

            // Select disclosures based on requested claim paths
            // Also include parent disclosures for nested paths (e.g., for "address.geo.lat", include "address.geo")
            var selectedDisclosureIndices = new HashSet<int>();
            IReadOnlyDictionary<string, int>? trustedNestedPaths = null;

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
                            // A top-level claim can literally contain dots. Suffix
                            // matching alone can disclose an unrelated opaque claim.
                            // Trust only paths proven by the signed nested structure.
                            if (kvp.Key.EndsWith($".{claimPath}", StringComparison.Ordinal) &&
                                (trustedNestedPaths ??= new DisclosureClaimPathMapper()
                                    .BuildNestedClaimPathMapping(sdJwt))
                                .TryGetValue(kvp.Key, out var trustedIndex) &&
                                trustedIndex == kvp.Value)
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
    /// <exception cref="ArgumentException">The presentation exceeds the verifier's limits or contains invalid wire components.</exception>
    public string FormatPresentation(SdJwtPresentation presentation)
    {
        ArgumentNullException.ThrowIfNull(presentation);

        // Build the combined format: JWT~disclosure1~disclosure2~...~keyBinding
        // Calculate total length to pre-allocate and avoid List<string> allocation
        const char separator = Constants.COMBINED_FORMAT_SEPARATOR;
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
            // A permissive SdJwtPresentation may hold a null component.
            // Report invalid input rather than exposing a NullReferenceException.
            if (disclosure is null)
            {
                throw new ArgumentException(
                    "Presentation contains a null disclosure component.",
                    nameof(presentation));
            }

            totalLength += disclosure.Length + 1;
        }

        if (totalLength > Constants.MAX_JWT_SIZE_BYTES)
        {
            throw new ArgumentException(
                $"Presentation exceeds the maximum allowed size of {Constants.MAX_JWT_SIZE_BYTES} bytes.",
                nameof(presentation));
        }

        // string.Length is a UTF-16 count, not a wire-byte count. Avoid a
        // second scan for small values that cannot exceed the UTF-8 byte cap
        // even with three bytes per UTF-16 code unit.
        if (totalLength > Constants.MAX_JWT_SIZE_BYTES / 3)
        {
            long utf8Length = (long)System.Text.Encoding.UTF8.GetByteCount(jwt)
                + 1 + System.Text.Encoding.UTF8.GetByteCount(keyBinding);
            foreach (var disclosure in disclosures)
            {
                utf8Length += System.Text.Encoding.UTF8.GetByteCount(disclosure) + 1;
            }

            if (utf8Length > Constants.MAX_JWT_SIZE_BYTES)
            {
                throw new ArgumentException(
                    $"Presentation exceeds the maximum allowed size of {Constants.MAX_JWT_SIZE_BYTES} bytes.",
                    nameof(presentation));
            }
        }

        // Enforce component shape only after the cheap size gate, avoiding
        // scans of unbounded caller strings. The verifier rejects extra or
        // blank tilde-delimited slots; holder serialization must not emit them.
        if (string.IsNullOrWhiteSpace(jwt) || jwt.Contains(separator) ||
            (keyBinding.Length > 0 &&
             (string.IsNullOrWhiteSpace(keyBinding) || keyBinding.Contains(separator))))
        {
            throw new ArgumentException(
                "Presentation contains an invalid JWT or key binding component.",
                nameof(presentation));
        }

        foreach (var disclosure in disclosures)
        {
            if (string.IsNullOrWhiteSpace(disclosure) || disclosure.Contains(separator))
            {
                throw new ArgumentException(
                    "Presentation contains an invalid disclosure component.",
                    nameof(presentation));
            }
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

