using HeroSdJwt.Models;
using HeroSdJwt.Presentation;

namespace HeroSdJwt.Extensions;

/// <summary>
/// Extension methods to simplify common SD-JWT operations.
/// </summary>
public static class SdJwtExtensions
{
    /// <summary>
    /// Creates a presentation string from an SD-JWT, revealing specific claims.
    /// This is a convenience method that combines CreatePresentation() and FormatPresentation().
    /// </summary>
    /// <param name="sdJwt">The SD-JWT to create a presentation from.</param>
    /// <param name="claimsToReveal">Names of claims to reveal in the presentation.</param>
    /// <returns>Formatted presentation string (JWT~disclosure1~disclosure2~...~).</returns>
    /// <example>
    /// <code>
    /// var sdJwt = SdJwtBuilder.Create()
    ///     .WithClaims(claims)
    ///     .MakeSelective("email", "age", "address")
    ///     .SignWithHmac(key)
    ///     .Build();
    ///
    /// // Simple presentation revealing only email and age
    /// var presentation = sdJwt.ToPresentation("email", "age");
    /// </code>
    /// </example>
    public static string ToPresentation(this SdJwt sdJwt, params string[] claimsToReveal)
    {
        ArgumentNullException.ThrowIfNull(sdJwt);

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentation(sdJwt, claimsToReveal, keyBindingJwt: null);
        return presenter.FormatPresentation(presentation);
    }

    /// <summary>
    /// Creates a presentation string from an SD-JWT with key binding.
    /// Includes a key binding JWT to prove holder possession of the private key.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT to create a presentation from.</param>
    /// <param name="keyBindingJwt">The key binding JWT proving holder possession.</param>
    /// <param name="claimsToReveal">Names of claims to reveal in the presentation.</param>
    /// <returns>Formatted presentation string with key binding.</returns>
    /// <example>
    /// <code>
    /// // Create key binding JWT
    /// var kbGenerator = new KeyBindingGenerator();
    /// var keyBindingJwt = kbGenerator.CreateKeyBindingJwt(
    ///     holderPrivateKey,
    ///     sdJwtHash,
    ///     audience,
    ///     nonce);
    ///
    /// // Create presentation with key binding
    /// var presentation = sdJwt.ToPresentationWithKeyBinding(keyBindingJwt, "email", "age");
    /// </code>
    /// </example>
    public static string ToPresentationWithKeyBinding(
        this SdJwt sdJwt,
        string keyBindingJwt,
        params string[] claimsToReveal)
    {
        ArgumentNullException.ThrowIfNull(sdJwt);
        ArgumentNullException.ThrowIfNull(keyBindingJwt);

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentation(sdJwt, claimsToReveal, keyBindingJwt);
        return presenter.FormatPresentation(presentation);
    }

    /// <summary>
    /// Creates a presentation revealing all selectively disclosed claims.
    /// Useful for testing or when all claims should be revealed.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT to create a presentation from.</param>
    /// <returns>Formatted presentation string with all disclosures.</returns>
    /// <example>
    /// <code>
    /// // Reveal everything
    /// var presentation = sdJwt.ToPresentationWithAllClaims();
    /// </code>
    /// </example>
    public static string ToPresentationWithAllClaims(this SdJwt sdJwt)
    {
        ArgumentNullException.ThrowIfNull(sdJwt);

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        return presenter.FormatPresentation(presentation);
    }
}
