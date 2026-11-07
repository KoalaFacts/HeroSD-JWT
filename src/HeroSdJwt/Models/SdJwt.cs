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
    // The 100-disclosure limit applies to presentations, not credentials:
    // holders may select a subset from a much larger issued credential.
    // Use an intentionally conservative, independent safety ceiling so a
    // hostile or non-terminating IEnumerable cannot grow this list forever.
    internal const int MAX_CREDENTIAL_DISCLOSURES = Constants.MAX_JWT_SIZE_BYTES;

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
    /// <exception cref="ArgumentException">Thrown for invalid wire components or if the disclosure count exceeds the supported limit.</exception>
    public SdJwt(string jwt, IEnumerable<string> disclosures, HashAlgorithm hashAlgorithm, string? keyBindingJwt = null, IReadOnlyDictionary<string, int>? claimPathMapping = null)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(disclosures);

        if (string.IsNullOrWhiteSpace(jwt))
        {
            throw new ArgumentException("JWT cannot be empty or whitespace.", nameof(jwt));
        }

        // The combined wire format reserves '~' as its component delimiter.
        // A caller-supplied compact JWT or KB-JWT must not inject new slots.
        if (jwt.Contains(Constants.COMBINED_FORMAT_SEPARATOR))
        {
            throw new ArgumentException("JWT cannot contain presentation separators.", nameof(jwt));
        }

        if (keyBindingJwt is { Length: > 0 } &&
            (string.IsNullOrWhiteSpace(keyBindingJwt) ||
             keyBindingJwt.Contains(Constants.COMBINED_FORMAT_SEPARATOR)))
        {
            throw new ArgumentException("Key binding JWT contains an invalid component.", nameof(keyBindingJwt));
        }

        // A combined presentation always includes at least one '~', even if
        // no claims are disclosed. Reject a JWT that could never fit on the
        // wire before consuming an untrusted disclosure enumerable.
        if (jwt.Length >= Constants.MAX_JWT_SIZE_BYTES ||
            (jwt.Length >= Constants.MAX_JWT_SIZE_BYTES / 3 &&
             System.Text.Encoding.UTF8.GetByteCount(jwt) >= Constants.MAX_JWT_SIZE_BYTES))
        {
            throw new ArgumentException(
                "JWT is too large to fit in a combined presentation.",
                nameof(jwt));
        }

        // An attached key binding JWT also occupies the mandatory minimum
        // presentation, before any optional disclosures are selected.
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

        // Do not eagerly materialize an unbounded lazy source. The
        // constructor must preserve the larger credential use case, but an
        // unbounded source still needs an independent admission ceiling.
        var ownedDisclosures = new List<string>();
        foreach (var disclosure in disclosures)
        {
            if (ownedDisclosures.Count >= MAX_CREDENTIAL_DISCLOSURES)
            {
                throw new ArgumentException(
                    $"SD-JWT exceeds the maximum of {MAX_CREDENTIAL_DISCLOSURES} disclosures.",
                    nameof(disclosures));
            }

            // Null/blank entries create empty disclosure slots, and '~' adds
            // extra slots to the combined format. Reject malformed components
            // before this credential can be turned into an invalid presentation.
            if (string.IsNullOrWhiteSpace(disclosure) || disclosure.Contains('~'))
            {
                throw new ArgumentException(
                    "Disclosures must be non-empty components without '~' separators.",
                    nameof(disclosures));
            }

            ownedDisclosures.Add(disclosure);
        }

        Jwt = jwt;
        Disclosures = new ReadOnlyCollection<string>(ownedDisclosures);
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

        // UTF-8 uses at most three bytes per UTF-16 code unit. Small combined
        // values therefore need no second scan. Larger non-ASCII components
        // must be measured in bytes, not string.Length, before serialization.
        if (combinedLength > Constants.MAX_JWT_SIZE_BYTES / 3)
        {
            long utf8Length = (long)System.Text.Encoding.UTF8.GetByteCount(Jwt)
                + 1 + System.Text.Encoding.UTF8.GetByteCount(KeyBindingJwt ?? string.Empty);
            foreach (var disclosure in Disclosures)
            {
                utf8Length += System.Text.Encoding.UTF8.GetByteCount(disclosure) + 1;
            }

            if (utf8Length > Constants.MAX_JWT_SIZE_BYTES)
            {
                throw new ArgumentException(
                    $"Presentation exceeds the maximum allowed size of {Constants.MAX_JWT_SIZE_BYTES} bytes.");
            }
        }

        // Write directly into the final string. Avoid allocating a list and
        // intermediate arrays for each holder presentation.
        var keyBinding = KeyBindingJwt ?? string.Empty;
        return string.Create((int)combinedLength, (jwt: Jwt, disclosures: Disclosures, keyBinding), (span, state) =>
        {
            var position = 0;
            state.jwt.AsSpan().CopyTo(span);
            position += state.jwt.Length;
            span[position++] = Constants.COMBINED_FORMAT_SEPARATOR;

            foreach (var disclosure in state.disclosures)
            {
                // Preserve string.Join's treatment of null entries as empty.
                var value = disclosure ?? string.Empty;
                value.AsSpan().CopyTo(span[position..]);
                position += value.Length;
                span[position++] = Constants.COMBINED_FORMAT_SEPARATOR;
            }

            state.keyBinding.AsSpan().CopyTo(span[position..]);
        });
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
