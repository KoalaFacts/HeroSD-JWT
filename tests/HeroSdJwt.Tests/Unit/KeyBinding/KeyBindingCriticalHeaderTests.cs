using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.KeyBinding;

/// <summary>
/// Signed JOSE extension regressions: a correct ES256 signature must not bypass
/// the mandatory processing of critical protected-header parameters (RFC 7515).
/// </summary>
public class KeyBindingCriticalHeaderTests
{
    private const string AUDIENCE = "https://verifier.example.test";
    private const string NONCE = "critical-header-challenge";
    private const string SD_HASH = "signed-credential-hash";

    [Theory]
    [InlineData("unknown-critical")]
    [InlineData("b64-critical")]
    [InlineData("empty-critical")]
    [InlineData("scalar-critical")]
    [InlineData("null-critical")]
    [InlineData("b64-without-critical")]
    public void Should_RejectSignedProofRequiringUnsupportedJoseHeaderProcessing(string mutation)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var header = new Dictionary<string, object?>
        {
            ["alg"] = "ES256",
            ["typ"] = "kb+jwt"
        };

        switch (mutation)
        {
            case "unknown-critical":
                header["crit"] = new[] { "unsupported-extension" };
                header["unsupported-extension"] = true;
                break;
            case "b64-critical":
                header["crit"] = new[] { "b64" };
                header["b64"] = false;
                break;
            case "empty-critical":
                header["crit"] = Array.Empty<string>();
                break;
            case "scalar-critical":
                header["crit"] = "unsupported-extension";
                header["unsupported-extension"] = true;
                break;
            case "null-critical":
                header["crit"] = null;
                break;
            case "b64-without-critical":
                header["b64"] = true;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        var proof = Sign(holder, header);
        Assert.False(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), SD_HASH, AUDIENCE, NONCE));
    }

    [Fact]
    public void Should_AllowSignedNoncriticalExtensionAndStandardGeneratedProof()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = holder.ExportSubjectPublicKeyInfo();
        var header = new Dictionary<string, object?>
        {
            ["alg"] = "ES256",
            ["typ"] = "kb+jwt",
            ["optional-extension"] = true
        };

        Assert.True(new KeyBindingValidator().ValidateKeyBinding(
            Sign(holder, header), publicKey, SD_HASH, AUDIENCE, NONCE));

        var generated = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), SD_HASH, AUDIENCE, NONCE);
        Assert.True(new KeyBindingValidator().ValidateKeyBinding(
            generated, publicKey, SD_HASH, AUDIENCE, NONCE));
    }

    private static string Sign(ECDsa holder, Dictionary<string, object?> header)
    {
        var payload = new
        {
            sd_hash = SD_HASH,
            aud = AUDIENCE,
            nonce = NONCE,
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var signingInput = Base64UrlEncoder.Encode(JsonSerializer.Serialize(header)) + "." +
            Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload));
        var signedBytes = System.Text.Encoding.UTF8.GetBytes(signingInput);
        var signature = holder.SignData(signedBytes, HashAlgorithmName.SHA256);

        // Ensure all negative cases carry a genuinely valid ES256 signature:
        // without this assertion, bad crypto could give a false-positive test.
        Assert.True(holder.VerifyData(signedBytes, signature, HashAlgorithmName.SHA256));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }
}
