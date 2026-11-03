using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Malformed escaped Unicode in a signed KB-JWT string must be rejected by
/// the boolean validation API, not surface as an InvalidOperationException.
/// </summary>
public sealed class KeyBindingMalformedStringEscapeTests
{
    private static readonly DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

    [Theory]
    [InlineData("alg", "\\uD800")]
    [InlineData("alg", "\\uDC00")]
    [InlineData("typ", "\\uD800")]
    [InlineData("typ", "\\uDC00")]
    [InlineData("sd_hash", "\\uD800")]
    [InlineData("sd_hash", "\\uDC00")]
    [InlineData("aud", "\\uD800")]
    [InlineData("aud", "\\uDC00")]
    [InlineData("nonce", "\\uD800")]
    [InlineData("nonce", "\\uDC00")]
    public void Should_RejectMalformedEscapedUnicode_InAuthenticatedKeyBindingStrings(
        string field, string escapedValue)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = SignProof(holder, field, escapedValue);
        var key = holder.ExportSubjectPublicKeyInfo();
        var validator = new KeyBindingValidator(new FixedTimeProvider(_now));

        Assert.False(validator.ValidateKeyBinding(proof, key, "hash", "aud", "nonce"));
        Assert.False(validator.ValidateKeyBinding(proof, key, "hash", ["aud"], "nonce"));
    }

    [Theory]
    [InlineData("sd_hash")]
    [InlineData("aud")]
    [InlineData("nonce")]
    public void Should_AcceptValidEscapedSurrogatePair_InAuthenticatedKeyBindingStrings(string field)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = SignProof(holder, field, "\\uD83D\\uDE00");
        var key = holder.ExportSubjectPublicKeyInfo();
        var expectedHash = field == "sd_hash" ? "\U0001F600" : "hash";
        var expectedAudience = field == "aud" ? "\U0001F600" : "aud";
        var expectedNonce = field == "nonce" ? "\U0001F600" : "nonce";
        var validator = new KeyBindingValidator(new FixedTimeProvider(_now));

        Assert.True(validator.ValidateKeyBinding(
            proof, key, expectedHash, expectedAudience, expectedNonce));
        Assert.True(validator.ValidateKeyBinding(
            proof, key, expectedHash, [expectedAudience], expectedNonce));
    }

    private static string SignProof(ECDsa holder, string field, string escapedValue)
    {
        var headerJson = """{"alg":"ES256","typ":"kb+jwt"}""";
        var payloadJson = """{"sd_hash":"hash","aud":"aud","nonce":"nonce","iat":1700000000}""";
        var normalValue = field switch
        {
            "alg" => "ES256",
            "typ" => "kb+jwt",
            "sd_hash" => "hash",
            "aud" => "aud",
            "nonce" => "nonce",
            _ => throw new ArgumentOutOfRangeException(nameof(field))
        };
        var originalMember = "\"" + field + "\":\"" + normalValue + "\"";
        var replacementMember = "\"" + field + "\":\"" + escapedValue + "\"";
        if (field is "alg" or "typ")
        {
            headerJson = headerJson.Replace(originalMember, replacementMember, StringComparison.Ordinal);
        }
        else
        {
            payloadJson = payloadJson.Replace(originalMember, replacementMember, StringComparison.Ordinal);
        }

        var signingInput = Base64UrlEncoder.Encode(headerJson) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signedBytes = System.Text.Encoding.ASCII.GetBytes(signingInput);
        var signature = holder.SignData(signedBytes, HashAlgorithmName.SHA256);
        Assert.True(holder.VerifyData(signedBytes, signature, HashAlgorithmName.SHA256));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
