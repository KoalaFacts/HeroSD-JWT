using HeroSdJwt.Models;

namespace HeroSdJwt.Presentation;

/// <summary>
/// Maps claim paths (e.g., "address.street") to their corresponding disclosures
/// by analyzing the JWT structure and matching disclosure digests.
/// </summary>
public interface IDisclosureClaimPathMapper
{
    /// <summary>
    /// Builds a mapping from user-friendly claim paths to disclosure indices.
    /// This enables ToPresentation() to work with nested and array element claims.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT containing JWT and disclosures.</param>
    /// <returns>Dictionary mapping claim paths to disclosure indices.</returns>
    Dictionary<string, int> BuildClaimPathMapping(SdJwt sdJwt);
}
