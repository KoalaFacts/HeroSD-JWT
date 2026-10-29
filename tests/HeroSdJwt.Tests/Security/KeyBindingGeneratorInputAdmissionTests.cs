using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A holder must not issue or accept a signed KB-JWT without the required
/// disclosure hash, audience or replay challenge.
/// </summary>
public class KeyBindingGeneratorInputAdmissionTests
{
    private const string AUDIENCE = "https://verifier.example.test";
    private const string NONCE = "one-time-challenge";

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
        var audience = parameterName == "audience" ? blankValue : AUDIENCE;
        var nonce = parameterName == "nonce" ? blankValue : NONCE;

        var error = Assert.Throws<ArgumentException>(() =>
            new KeyBindingGenerator().CreateKeyBindingJwt(
                holder.ExportECPrivateKey(), sdJwtHash, audience, nonce));

        Assert.Equal(parameterName, error.ParamName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Should_RejectSignedHolderProofWhenSdHashAndExpectedHashAreBlank(string blankHash)
    {
        // Deliberately sign the otherwise well-formed proof without using
        // KeyBindingGenerator: the generator itself must reject this input.
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var header = Base64UrlEncoder.Encode("{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}");
        var payload = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new
        {
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            aud = AUDIENCE,
            nonce = NONCE,
            sd_hash = blankHash
        }));
        var signingInput = $"{header}.{payload}";
        var signature = holder.SignData(
            System.Text.Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256);
        var proof = $"{signingInput}.{Base64UrlEncoder.Encode(signature)}";

        Assert.False(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), blankHash, AUDIENCE, NONCE));
    }
}
