using HeroSdJwt.Presentation;
using System.Security.Cryptography;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A selectable parent must wrap its already-redacted children. Issuing a
/// disclosure from the original parent value leaks independently selective
/// nested properties and array elements to a holder's relying party.
/// </summary>
public class OverlappingSelectivePathPrivacyTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Should_KeepNestedLeafPrivate_WhenParentAndLeafAreBothSelective(bool parentFirst)
    {
        var signingKey = RandomNumberGenerator.GetBytes(32);
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "holder-1",
            ["profile"] = new
            {
                display = "Alice",
                contact = new { email = "secret@example.com", phone = "555-0100" }
            }
        };
        string[] selectedPaths = parentFirst
            ? ["profile", "profile.contact.email"]
            : ["profile.contact.email", "profile"];

        var sdJwt = TestHelpers.CreateIssuer().CreateSdJwt(
            claims, selectedPaths, signingKey, HashAlgorithm.Sha256);

        var parser = new DisclosureParser();
        var parent = Assert.Single(sdJwt.Disclosures, d => parser.GetClaimName(d) == "profile");
        var parentValue = parser.Parse(parent).ClaimValue;

        Assert.Equal("Alice", parentValue.GetProperty("display").GetString());
        Assert.False(parentValue.TryGetProperty("contact", out _));
        Assert.Equal(JsonValueKind.Array, parentValue.GetProperty("_sd").ValueKind);

        var presenter = new SdJwtPresenter();
        var parentOnly = presenter.CreatePresentation(sdJwt, ["profile"]);
        Assert.Single(parentOnly.SelectedDisclosures);
        Assert.True(TestHelpers.CreateVerifier().VerifyPresentation(
            presenter.FormatPresentation(parentOnly), signingKey).IsValid);

        var withEmail = presenter.CreatePresentation(sdJwt, ["profile.contact.email"]);
        Assert.Equal(3, withEmail.SelectedDisclosures.Count);
        Assert.True(TestHelpers.CreateVerifier().VerifyPresentation(
            presenter.FormatPresentation(withEmail), signingKey).IsValid);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Should_KeepArrayElementPrivate_WhenArrayAndElementAreBothSelective(bool parentFirst)
    {
        var signingKey = RandomNumberGenerator.GetBytes(32);
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "holder-1",
            ["roles"] = new[] { "viewer", "secret-admin", "editor" }
        };
        string[] selectedPaths = parentFirst
            ? ["roles", "roles[1]"]
            : ["roles[1]", "roles"];

        var sdJwt = TestHelpers.CreateIssuer().CreateSdJwt(
            claims, selectedPaths, signingKey, HashAlgorithm.Sha256);

        var parser = new DisclosureParser();
        var parent = Assert.Single(sdJwt.Disclosures, d => parser.GetClaimName(d) == "roles");
        var parentValue = parser.Parse(parent).ClaimValue;

        Assert.Equal("viewer", parentValue[0].GetString());
        Assert.Equal(JsonValueKind.Object, parentValue[1].ValueKind);
        Assert.Equal(JsonValueKind.String, parentValue[1].GetProperty("...").ValueKind);
        Assert.Equal("editor", parentValue[2].GetString());

        var presenter = new SdJwtPresenter();
        var parentOnly = presenter.CreatePresentation(sdJwt, ["roles"]);
        Assert.Single(parentOnly.SelectedDisclosures);
        Assert.True(TestHelpers.CreateVerifier().VerifyPresentation(
            presenter.FormatPresentation(parentOnly), signingKey).IsValid);

        var withElement = presenter.CreatePresentation(sdJwt, ["roles[1]"]);
        Assert.Equal(2, withElement.SelectedDisclosures.Count);
        Assert.True(TestHelpers.CreateVerifier().VerifyPresentation(
            presenter.FormatPresentation(withElement), signingKey).IsValid);
    }
}
