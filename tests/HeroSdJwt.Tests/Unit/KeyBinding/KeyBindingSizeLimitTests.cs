using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.KeyBinding;

/// <summary>
/// Ensures the public key-binding verifier applies the presentation-size budget
/// even when invoked directly, outside the SD-JWT verifier.
/// </summary>
public class KeyBindingSizeLimitTests
{
    private const string AUDIENCE = "https://verifier.example.test";
    private const string SD_HASH = "test-sd-hash";

    [Theory]
    [InlineData(128, true)]
    [InlineData(Constants.MAX_JWT_SIZE_BYTES, false)]
    public void Should_EnforceSizeLimitForGenuinelySignedKeyBindingJwt(int nonceLength, bool accepted)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var nonce = new string('n', nonceLength);
        var header = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { alg = "ES256", typ = "kb+jwt" }));
        var payload = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new
        {
            sd_hash = SD_HASH,
            aud = AUDIENCE,
            nonce,
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        }));
        var signingInput = $"{header}.{payload}";
        var data = System.Text.Encoding.UTF8.GetBytes(signingInput);
        var signature = holder.SignData(data, HashAlgorithmName.SHA256);
        Assert.True(holder.VerifyData(data, signature, HashAlgorithmName.SHA256));

        var proof = $"{signingInput}.{Base64UrlEncoder.Encode(signature)}";
        Assert.Equal(accepted, proof.Length <= Constants.MAX_JWT_SIZE_BYTES);

        // Before the fix the over-budget proof, whose signature and claims
        // really are valid, was accepted by the direct validator.
        Assert.Equal(accepted, new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), SD_HASH, AUDIENCE, nonce));
    }
}
