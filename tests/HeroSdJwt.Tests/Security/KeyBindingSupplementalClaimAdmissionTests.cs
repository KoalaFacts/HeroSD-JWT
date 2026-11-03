using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A signed holder proof must not admit ambiguous or undecodable supplemental
/// claims that downstream consumers could interpret differently.
/// </summary>
public sealed class KeyBindingSupplementalClaimAdmissionTests
{
    private static readonly DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

    [Theory]
    [InlineData("\"extra\":\"\\uD800\"")]
    [InlineData("\"extra\":{\"nested\":\"\\uDC00\"}")]
    [InlineData("\"extra\":{\"role\":\"user\",\"role\":\"admin\"}")]
    [InlineData("\"extra\":[{\"role\":\"user\",\"\\u0072ole\":\"admin\"}]")]
    public void Should_RejectMalformedOrAmbiguousSignedSupplementalClaims(string extraClaimJson)
    {
        AssertProofValid(extraClaimJson, expected: false);
    }

    [Theory]
    [InlineData("\"extra\":{\"roles\":[\"viewer\",\"editor\"]}")]
    [InlineData("\"extra\":{\"nested\":\"\\uD83D\\uDE00\"}")]
    public void Should_AcceptUnambiguousSignedSupplementalClaims(string extraClaimJson)
    {
        AssertProofValid(extraClaimJson, expected: true);
    }

    private static void AssertProofValid(string extraClaimJson, bool expected)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var header = Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"alg":"ES256","typ":"kb+jwt"}""");
        var payload = "{\"sd_hash\":\"hash\",\"aud\":\"aud\",\"nonce\":\"nonce\",\"iat\":1700000000," +
            extraClaimJson + "}";
        var signingInput = header + "." + Base64UrlEncoder.Encode(payload);
        var signedBytes = System.Text.Encoding.ASCII.GetBytes(signingInput);
        var signature = holder.SignData(signedBytes, HashAlgorithmName.SHA256);
        Assert.True(holder.VerifyData(signedBytes, signature, HashAlgorithmName.SHA256));

        var proof = signingInput + "." + Base64UrlEncoder.Encode(signature);
        var validator = new KeyBindingValidator(new FixedTimeProvider(_now));
        var publicKey = holder.ExportSubjectPublicKeyInfo();

        Assert.Equal(expected, validator.ValidateKeyBinding(proof, publicKey, "hash", "aud", "nonce"));
        Assert.Equal(expected, validator.ValidateKeyBinding(proof, publicKey, "hash", ["aud"], "nonce"));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
