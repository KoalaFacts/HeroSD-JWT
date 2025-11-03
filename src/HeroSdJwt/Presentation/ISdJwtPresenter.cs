using HeroSdJwt.Models;

namespace HeroSdJwt.Presentation;

/// <summary>
/// Creates presentations from SD-JWTs by selecting which claims to disclose.
/// </summary>
public interface ISdJwtPresenter
{
    /// <summary>
    /// Creates a presentation with the specified selected claims.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT to present.</param>
    /// <param name="selectedClaimNames">The names of claims to disclose.</param>
    /// <param name="keyBindingJwt">Optional key binding JWT to prove holder possession of private key.</param>
    /// <returns>The presentation containing only selected disclosures.</returns>
    SdJwtPresentation CreatePresentation(
        SdJwt sdJwt,
        IEnumerable<string> selectedClaimNames,
        string? keyBindingJwt = null);

    /// <summary>
    /// Creates a presentation with all disclosures included.
    /// Convenience method for full disclosure.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT to present.</param>
    /// <param name="keyBindingJwt">Optional key binding JWT to prove holder possession of private key.</param>
    /// <returns>The presentation containing all disclosures.</returns>
    SdJwtPresentation CreatePresentationWithAllClaims(SdJwt sdJwt, string? keyBindingJwt = null);

    /// <summary>
    /// Formats a presentation as a tilde-separated string.
    /// Format: {JWT}~{disclosure1}~{disclosure2}~...~{keyBindingJwt}
    /// </summary>
    /// <param name="presentation">The presentation to format.</param>
    /// <returns>The formatted presentation string.</returns>
    string FormatPresentation(SdJwtPresentation presentation);
}
