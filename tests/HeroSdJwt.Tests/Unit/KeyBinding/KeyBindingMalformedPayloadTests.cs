using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.KeyBinding;

/// <summary>
/// Regressions for cryptographically signed KB-JWTs with malformed claim types.
/// Invalid untrusted JSON must produce a false validation result, not an exception.
/// </summary>
public class KeyBindingMalformedPayloadTests
{
    private const string AUDIENCE = "https://verifier.example.test";
    private const string NONCE = "independent-holder-challenge";
    private const string SD_HASH = "signed-sd-jwt-digest";

    [Theory]
    [InlineData("payload-array")]
    [InlineData("payload-string")]
    [InlineData("sd-hash-number")]
    [InlineData("sd-hash-null")]
    [InlineData("sd-hash-object")]
    [InlineData("nonce-bool")]
    [InlineData("nonce-null")]
    [InlineData("nonce-array")]
    [InlineData("iat-string")]
    [InlineData("iat-bool")]
    [InlineData("iat-null")]
    [InlineData("iat-decimal")]
    [InlineData("iat-object")]
    [InlineData("iat-max")]
    [InlineData("iat-min")]
    public void Should_RejectMalformedSignedKeyBindingPayloadWithoutThrowing(string mutation)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var claims = new Dictionary<string, object?>
        {
            ["sd_hash"] = SD_HASH,
            ["aud"] = AUDIENCE,
            ["nonce"] = NONCE,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var payloadJson = mutation switch
        {
            "payload-array" => JsonSerializer.Serialize(new[] { "not-an-object" }),
            "payload-string" => JsonSerializer.Serialize("not-an-object"),
            _ => SerializeMutatedClaims(claims, mutation)
        };
        var headerJson = JsonSerializer.Serialize(new { alg = "ES256", typ = "kb+jwt" });
        var signingInput = Base64UrlEncoder.Encode(headerJson) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signedBytes = System.Text.Encoding.UTF8.GetBytes(signingInput);
        var signature = holder.SignData(signedBytes, HashAlgorithmName.SHA256);

        // The signature is genuinely valid for the mutated header and payload.
        // Rejection must come from payload validation, not a broken signature.
        Assert.True(holder.VerifyData(signedBytes, signature, HashAlgorithmName.SHA256));
        var proof = signingInput + "." + Base64UrlEncoder.Encode(signature);

        Assert.False(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), SD_HASH, AUDIENCE, NONCE));
    }

    [Fact]
    public void Should_AcceptWellFormedSignedKeyBindingPayload()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), SD_HASH, AUDIENCE, NONCE);

        Assert.True(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), SD_HASH, AUDIENCE, NONCE));
    }

    private static string SerializeMutatedClaims(Dictionary<string, object?> claims, string mutation)
    {
        switch (mutation)
        {
            case "sd-hash-number":
                claims["sd_hash"] = 42;
                break;
            case "sd-hash-null":
                claims["sd_hash"] = null;
                break;
            case "sd-hash-object":
                claims["sd_hash"] = new { unexpected = true };
                break;
            case "nonce-bool":
                claims["nonce"] = true;
                break;
            case "nonce-null":
                claims["nonce"] = null;
                break;
            case "nonce-array":
                claims["nonce"] = new[] { "not-a-string" };
                break;
            case "iat-string":
                claims["iat"] = "123";
                break;
            case "iat-bool":
                claims["iat"] = false;
                break;
            case "iat-null":
                claims["iat"] = null;
                break;
            case "iat-decimal":
                claims["iat"] = 123.5;
                break;
            case "iat-object":
                claims["iat"] = new { not_a_timestamp = true };
                break;
            case "iat-max":
                claims["iat"] = long.MaxValue;
                break;
            case "iat-min":
                claims["iat"] = long.MinValue;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        return JsonSerializer.Serialize(claims);
    }
}
