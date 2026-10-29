using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A holder must not issue a signed KB-JWT without the required disclosure hash,
/// audience or replay challenge: the verifier will reject such a proof.
/// </summary>
public class KeyBindingGeneratorInputAdmissionTests
{
    [Theory]
    [InlineData("sdJwtHash", "")]
    [InlineData("sdJwtHash", "   ")]
    [InlineData("audience", "")]
    [InlineData("audience", "   ")]
    [InlineData("nonce", "")]
    [InlineData("nonce", "   ")]
    public void Should_RejectBlankRequiredHolderBindingInputs(string parameterName, string blankValue)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var sdJwtHash = parameterName == "sdJwtHash" ? blankValue : "disclosure-hash";
        var audience = parameterName == "audience" ? blankValue : "https://verifier.example.test";
        var nonce = parameterName == "nonce" ? blankValue : "one-time-challenge";

        var error = Assert.Throws<ArgumentException>(() =>
            new KeyBindingGenerator().CreateKeyBindingJwt(
                holder.ExportECPrivateKey(), sdJwtHash, audience, nonce));

        Assert.Equal(parameterName, error.ParamName);
    }
}
