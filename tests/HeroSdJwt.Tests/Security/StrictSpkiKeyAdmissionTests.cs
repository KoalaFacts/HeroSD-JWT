using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// ImportSubjectPublicKeyInfo consumes only the first ASN.1 value. Verification
/// must reject trailing bytes rather than treating distinct key blobs as the
/// same trusted verification key.
/// </summary>
public class StrictSpkiKeyAdmissionTests
{
    [Theory]
    [InlineData("RS256")]
    [InlineData("PS256")]
    [InlineData("ES256")]
    [InlineData("ES384")]
    [InlineData("ES512")]
    public void Should_RejectTrailingBytesAfterValidSpki_When_VerifyingSignedJwt(string algorithm)
    {
        byte[] publicKey;
        byte[] signature;
        var encodedHeader = Base64UrlEncoder.Encode("{\"alg\":\"" + algorithm + "\",\"typ\":\"JWT\"}");
        var encodedPayload = Base64UrlEncoder.Encode("{\"sub\":\"subject\"}");
        var signingInput = encodedHeader + "." + encodedPayload;
        var data = Encoding.UTF8.GetBytes(signingInput);

        if (algorithm is "RS256" or "PS256")
        {
            using var rsa = RSA.Create(2048);
            publicKey = rsa.ExportSubjectPublicKeyInfo();
            signature = rsa.SignData(
                data,
                HashAlgorithmName.SHA256,
                algorithm == "RS256" ? RSASignaturePadding.Pkcs1 : RSASignaturePadding.Pss);
        }
        else
        {
            var curve = algorithm switch
            {
                "ES256" => ECCurve.NamedCurves.nistP256,
                "ES384" => ECCurve.NamedCurves.nistP384,
                _ => ECCurve.NamedCurves.nistP521
            };
            var hash = algorithm switch
            {
                "ES256" => HashAlgorithmName.SHA256,
                "ES384" => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA512
            };
            using var ecdsa = ECDsa.Create(curve);
            publicKey = ecdsa.ExportSubjectPublicKeyInfo();
            signature = ecdsa.SignData(data, hash);
        }

        var jwt = signingInput + "." + Base64UrlEncoder.Encode(signature);
        var validator = new SignatureValidator();
        Assert.True(validator.VerifyJwtSignature(jwt, publicKey));

        byte[] trailingKey = [.. publicKey, 0x00, 0x01];
        Assert.False(validator.VerifyJwtSignature(jwt, trailingKey));
    }

    [Fact]
    public void Should_RejectTrailingBytesAfterValidSpki_When_VerifyingHolderProof()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string hash = "credential-digest";
        const string audience = "https://verifier.example.test";
        const string nonce = "challenge";
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), hash, audience, nonce);
        var publicKey = holder.ExportSubjectPublicKeyInfo();
        var validator = new KeyBindingValidator();

        Assert.True(validator.ValidateKeyBinding(proof, publicKey, hash, audience, nonce));
        byte[] trailingKey = [.. publicKey, 0x00, 0x01];
        Assert.False(validator.ValidateKeyBinding(proof, trailingKey, hash, audience, nonce));
    }
}
