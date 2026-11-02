using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A holder must not serialize additional tilde-delimited slots that the
/// verifier would interpret as a different presentation structure.
/// </summary>
public class CombinedFormatComponentAdmissionTests
{
    private const string ValidJwt = "header.payload.signature";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \t")]
    [InlineData("~")]
    [InlineData("W10~W11")]
    public void Should_RejectInvalidDisclosureComponents_BeforeFormatting(string? disclosure)
    {
        // The presentation model is a permissive container; formatting is the
        // boundary at which invalid wire components must be rejected.
        var presentation = new SdJwtPresentation(ValidJwt, [disclosure!]);

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter().FormatPresentation(presentation));

        Assert.Equal("presentation", error.ParamName);
    }

    [Theory]
    [InlineData("~")]
    [InlineData("header~extra.payload.signature")]
    public void Should_RejectEmbeddedDelimiter_InCredentialJwt(string jwt)
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt(jwt, [], HashAlgorithm.Sha256));

        Assert.Equal("jwt", error.ParamName);
    }

    [Theory]
    [InlineData("~")]
    [InlineData("kb.jwt.signature~extra")]
    public void Should_RejectEmbeddedDelimiter_InCredentialKeyBinding(string keyBindingJwt)
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt(ValidJwt, [], HashAlgorithm.Sha256, keyBindingJwt));

        Assert.Equal("keyBindingJwt", error.ParamName);
    }

    [Theory]
    [InlineData("~")]
    [InlineData("header~extra.payload.signature")]
    public void Should_RejectEmbeddedDelimiter_InPresentationJwt(string jwt)
    {
        var presentation = new SdJwtPresentation(jwt, []);

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter().FormatPresentation(presentation));

        Assert.Equal("presentation", error.ParamName);
    }

    [Theory]
    [InlineData("~")]
    [InlineData("kb.jwt.signature~extra")]
    public void Should_RejectEmbeddedDelimiter_InPresentationKeyBinding(string keyBindingJwt)
    {
        var presentation = new SdJwtPresentation(ValidJwt, [], keyBindingJwt);

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter().FormatPresentation(presentation));

        Assert.Equal("presentation", error.ParamName);
    }

    [Fact]
    public void Should_PreserveValidComponentSlots_InBothSerializers()
    {
        var sdJwt = new SdJwt(ValidJwt, ["W10", "W11"], HashAlgorithm.Sha256, "kb.jwt.signature");
        var presentation = new SdJwtPresentation(ValidJwt, ["W10", "W11"], "kb.jwt.signature");
        const string expected = "header.payload.signature~W10~W11~kb.jwt.signature";

        Assert.Equal(expected, sdJwt.ToCombinedFormat());
        Assert.Equal(expected, new SdJwtPresenter().FormatPresentation(presentation));
        Assert.Equal(ValidJwt + "~W10~W11~", new SdJwtPresenter().FormatPresentation(
            new SdJwtPresentation(ValidJwt, ["W10", "W11"], string.Empty)));
    }
}
