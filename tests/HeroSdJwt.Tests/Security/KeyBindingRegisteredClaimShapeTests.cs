using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A KB-JWT is a JWT under RFC 9901. RFC 7519 requires iss, sub and jti
/// to be strings whenever present, even if the verifier does not use them
/// for a separate matching or revocation policy.
/// </summary>
public class KeyBindingRegisteredClaimShapeTests
{
    private static readonly DateTimeOffset _now =
        DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).AddMilliseconds(500);

    [Theory]
    [InlineData(",\"iss\":42", false)]
    [InlineData(",\"iss\":null", false)]
    [InlineData(",\"iss\":true", false)]
    [InlineData(",\"iss\":[]", false)]
    [InlineData(",\"iss\":{}", false)]
    [InlineData(",\"sub\":42", false)]
    [InlineData(",\"sub\":null", false)]
    [InlineData(",\"sub\":false", false)]
    [InlineData(",\"sub\":[]", false)]
    [InlineData(",\"sub\":{}", false)]
    [InlineData(",\"jti\":42", false)]
    [InlineData(",\"jti\":null", false)]
    [InlineData(",\"jti\":true", false)]
    [InlineData(",\"jti\":[]", false)]
    [InlineData(",\"jti\":{}", false)]
    [InlineData(",\"\\u0069ss\":42", false)]
    [InlineData(",\"s\\u0075b\":null", false)]
    [InlineData(",\"j\\u0074i\":{}", false)]
    [InlineData("", true)]
    [InlineData(",\"iss\":\"issuer\"", true)]
    [InlineData(",\"sub\":\"holder\"", true)]
    [InlineData(",\"jti\":\"proof-123\"", true)]
    [InlineData(",\"iss\":\"issuer\",\"sub\":\"holder\",\"jti\":\"proof-123\"", true)]
    public void Should_RequireOptionalRegisteredStringClaims_WhenHolderProofIsSigned(
        string optionalClaimsJson, bool expected)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var header = Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"alg":"ES256","typ":"kb+jwt"}""");
        var payloadJson = "{\"sd_hash\":\"hash\",\"aud\":\"aud\",\"nonce\":\"nonce\",\"iat\":1700000000" +
            optionalClaimsJson + "}";
        var signingInput = header + "." + Base64UrlEncoder.Encode(payloadJson);
        var signingBytes = System.Text.Encoding.UTF8.GetBytes(signingInput);
        var signature = holder.SignData(signingBytes, HashAlgorithmName.SHA256);
        var proof = signingInput + "." + Base64UrlEncoder.Encode(signature);

        Assert.True(holder.VerifyData(signingBytes, signature, HashAlgorithmName.SHA256));
        var validator = new KeyBindingValidator(new FixedTimeProvider(_now));
        var publicKey = holder.ExportSubjectPublicKeyInfo();

        Assert.Equal(expected, validator.ValidateKeyBinding(
            proof, publicKey, "hash", "aud", "nonce"));
        Assert.Equal(expected, validator.ValidateKeyBinding(
            proof, publicKey, "hash", ["other-aud", "aud"], "nonce"));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
