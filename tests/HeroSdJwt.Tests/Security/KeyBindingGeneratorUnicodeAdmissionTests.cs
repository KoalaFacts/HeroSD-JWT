using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Holder proof generation must not silently replace malformed UTF-16 in
/// binding claims: the signed audience, nonce and hash must be the inputs.
/// </summary>
public sealed class KeyBindingGeneratorUnicodeAdmissionTests
{
    [Theory]
    [InlineData("sdJwtHash", "\uD800")]
    [InlineData("sdJwtHash", "\uDC00")]
    [InlineData("audience", "\uD800")]
    [InlineData("audience", "\uDC00")]
    [InlineData("nonce", "\uD800")]
    [InlineData("nonce", "\uDC00")]
    public void Should_RejectUnpairedUtf16Surrogates_BeforeSigning(
        string parameterName, string malformed)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var hash = parameterName == "sdJwtHash" ? malformed : "hash";
        var audience = parameterName == "audience" ? malformed : "aud";
        var nonce = parameterName == "nonce" ? malformed : "nonce";

        var exception = Assert.Throws<ArgumentException>(() =>
            new KeyBindingGenerator().CreateKeyBindingJwt(
                holder.ExportECPrivateKey(), hash, audience, nonce));

        Assert.Equal(parameterName, exception.ParamName);
    }

    [Fact]
    public void Should_PreserveValidSurrogatePairs_InHolderBindingClaims()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string hash = "hash-\U0001F600";
        const string audience = "aud-\U0001F600";
        const string nonce = "nonce-\U0001F600";

        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), hash, audience, nonce);

        Assert.True(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), hash, audience, nonce));
    }
}
