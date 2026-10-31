using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The holder proof generator must not sign a KB-JWT that the matching
/// standalone verifier rejects solely because of its encoded wire size.
/// </summary>
public sealed class KeyBindingGeneratorSizeAdmissionTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Should_RejectHolderProofExceedingExistingVerifierSizeBudget(bool oversizedAudience)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var audience = oversizedAudience
            ? new string('a', Constants.MAX_JWT_SIZE_BYTES)
            : "https://verifier.example.test";
        var nonce = oversizedAudience
            ? "one-time-challenge"
            : new string('n', Constants.MAX_JWT_SIZE_BYTES);

        // Before the fix this returns a correctly signed, unusable KB-JWT:
        // KeyBindingValidator rejects it at its existing 64-KiB boundary.
        _ = Assert.Throws<ArgumentException>(() =>
            new KeyBindingGenerator().CreateKeyBindingJwt(
                holder.ExportECPrivateKey(), "hash", audience, nonce));
    }

    [Fact]
    public void Should_PreserveNormalSizedHolderProofGenerationAndValidation()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string audience = "https://verifier.example.test";
        const string nonce = "one-time-challenge";
        const string sdHash = "hash";

        var jwt = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), sdHash, audience, nonce);

        Assert.True(jwt.Length <= Constants.MAX_JWT_SIZE_BYTES);
        Assert.True(new KeyBindingValidator().ValidateKeyBinding(
            jwt, holder.ExportSubjectPublicKeyInfo(), sdHash, audience, nonce));
    }
}
