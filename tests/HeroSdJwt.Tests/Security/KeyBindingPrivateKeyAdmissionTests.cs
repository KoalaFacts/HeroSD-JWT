using HeroSdJwt.Cryptography;
using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The holder proof generator must accept the library's PKCS#8 EC keys as
/// well as existing SEC1 keys, but reject unconsumed ASN.1 suffix bytes.
/// </summary>
public class KeyBindingPrivateKeyAdmissionTests
{
    [Fact]
    public void Should_CreateVerifiableKeyBindingFromGeneratedPkcs8Key()
    {
        var (privateKey, publicKey) = KeyGenerator.Instance.GenerateEcdsaKeyPair();
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            privateKey, "sd-hash", "https://verifier.example.test", "unique-nonce");

        Assert.True(new KeyBindingValidator().ValidateKeyBinding(
            proof, publicKey, "sd-hash", "https://verifier.example.test", "unique-nonce"));
    }

    [Fact]
    public void Should_KeepExistingSec1HolderKeysInteroperable()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            key.ExportECPrivateKey(), "sd-hash", "https://verifier.example.test", "unique-nonce");

        Assert.True(new KeyBindingValidator().ValidateKeyBinding(
            proof, key.ExportSubjectPublicKeyInfo(), "sd-hash", "https://verifier.example.test", "unique-nonce"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectTrailingBytesAfterEcPrivateKey(bool pkcs8)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = pkcs8 ? key.ExportPkcs8PrivateKey() : key.ExportECPrivateKey();
        byte[] trailingBytes = [0x00, 0x30, 0xFF];

        foreach (var trailingByte in trailingBytes)
        {
            byte[] malformed = [.. privateKey, trailingByte];
            Assert.Throws<ArgumentException>(() =>
                new KeyBindingGenerator().CreateKeyBindingJwt(
                    malformed, "sd-hash", "https://verifier.example.test", "unique-nonce"));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectNonP256HolderKeysInBothFormats(bool pkcs8)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = pkcs8 ? key.ExportPkcs8PrivateKey() : key.ExportECPrivateKey();

        Assert.Throws<ArgumentException>(() =>
            new KeyBindingGenerator().CreateKeyBindingJwt(
                privateKey, "sd-hash", "https://verifier.example.test", "unique-nonce"));
    }
}
