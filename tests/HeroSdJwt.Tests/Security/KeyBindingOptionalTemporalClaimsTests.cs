using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A KB-JWT is a JWT under RFC 9901 Section 4.3. Optional registered
/// expiration and not-before claims must be enforced when present, even
/// when the holder proof has a valid ES256 signature and a fresh iat.
/// </summary>
public class KeyBindingOptionalTemporalClaimsTests
{
    private static readonly DateTimeOffset _now =
        DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).AddMilliseconds(500);

    [Theory]
    [InlineData("", true)]
    [InlineData(",\"exp\":1700000060", true)]
    [InlineData(",\"exp\":1700000000.50000001", true)]
    [InlineData(",\"exp\":1700000000.5", false)]
    [InlineData(",\"exp\":1700000000.49999999", false)]
    [InlineData(",\"exp\":1699999999", false)]
    [InlineData(",\"exp\":\"1700000060\"", false)]
    [InlineData(",\"exp\":null", false)]
    [InlineData(",\"exp\":true", false)]
    [InlineData(",\"exp\":1e400", false)]
    [InlineData(",\"nbf\":1699999999", true)]
    [InlineData(",\"nbf\":1700000000.5", true)]
    [InlineData(",\"nbf\":1700000000.50000001", false)]
    [InlineData(",\"nbf\":1700000060", false)]
    [InlineData(",\"nbf\":\"1699999999\"", false)]
    [InlineData(",\"nbf\":null", false)]
    [InlineData(",\"nbf\":false", false)]
    [InlineData(",\"nbf\":1e400", false)]
    [InlineData(",\"nbf\":1699999999,\"exp\":1700000060", true)]
    [InlineData(",\"nbf\":1700000060,\"exp\":1700000060", false)]
    public void Should_ValidateOptionalExpAndNbf_WhenKeyBindingJwtIsGenuinelySigned(
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

        Assert.Equal(expected, validator.ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), "hash", "aud", "nonce"));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
