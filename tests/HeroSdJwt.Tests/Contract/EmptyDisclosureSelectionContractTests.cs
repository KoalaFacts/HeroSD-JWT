using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// An empty holder selection does not require inspecting the signed disclosure
/// paths. Imported credentials must not rebuild their mapping to reveal nothing.
/// </summary>
public sealed class EmptyDisclosureSelectionContractTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_SkipClaimMapping_When_NoDisclosuresAreSelected(bool overrideKeyBinding)
    {
        var issued = SdJwtIssuerBuilder.Create()
            .WithClaim("email", "secret@example.test")
            .MakeSelective("email")
            .SignWithHmac(KeyGenerator.Instance.GenerateHmacKey())
            .Build();

        // Imported credentials have no issuance-time cached claim-path mapping.
        var imported = new SdJwt(
            issued.Jwt,
            issued.Disclosures,
            issued.HashAlgorithm,
            keyBindingJwt: "original.kb.jwt");
        var mapper = new CountingMapper();
        var presenter = new SdJwtPresenter(mapper);
        var replacement = overrideKeyBinding ? "replacement.kb.jwt" : null;

        var presentation = presenter.CreatePresentation(imported, [], replacement);

        Assert.Equal(0, mapper.CallCount);
        Assert.Empty(presentation.SelectedDisclosures);
        Assert.Equal(imported.Jwt, presentation.Jwt);
        Assert.Equal(replacement ?? imported.KeyBindingJwt, presentation.KeyBindingJwt);
        Assert.Equal(
            $"{imported.Jwt}~{replacement ?? imported.KeyBindingJwt}",
            presenter.FormatPresentation(presentation));
    }

    [Fact]
    public void Should_StillMapSelectedDisclosures_When_ImportedCredentialHasNoMapping()
    {
        var issued = SdJwtIssuerBuilder.Create()
            .WithClaim("email", "secret@example.test")
            .MakeSelective("email")
            .SignWithHmac(KeyGenerator.Instance.GenerateHmacKey())
            .Build();
        var imported = new SdJwt(issued.Jwt, issued.Disclosures, issued.HashAlgorithm);
        var mapper = new CountingMapper();
        var presenter = new SdJwtPresenter(mapper);

        var presentation = presenter.CreatePresentation(imported, ["email"]);

        Assert.Equal(1, mapper.CallCount);
        Assert.Equal(Assert.Single(imported.Disclosures), Assert.Single(presentation.SelectedDisclosures));
    }

    private sealed class CountingMapper : IDisclosureClaimPathMapper
    {
        public int CallCount { get; private set; }

        public Dictionary<string, int> BuildClaimPathMapping(SdJwt sdJwt)
        {
            CallCount++;
            return new Dictionary<string, int>(StringComparer.Ordinal) { ["email"] = 0 };
        }
    }
}
