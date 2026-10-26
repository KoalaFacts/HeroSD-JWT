using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 7519 NumericDate permits non-integer seconds. Valid signed credentials
/// must interoperate without widening the accepted freshness/expiry windows.
/// </summary>
public class NumericDateInteroperabilityTests
{
    private static readonly DateTimeOffset _fixedNow =
        DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).AddMilliseconds(500);

    [Theory]
    [InlineData("""{"exp":1700000000.75,"nbf":1700000000.25,"iat":1700000000.25}""", true)]
    [InlineData("""{"exp":1700000000.5,"nbf":1700000000.5,"iat":1700000000.5}""", true)]
    [InlineData("""{"exp":1700000000.50000001}""", true)]
    [InlineData("""{"exp":1700000000.49999999}""", false)]
    [InlineData("""{"exp":1700000001,"nbf":1700000000.50000001}""", false)]
    [InlineData("""{"exp":1700000001,"iat":1700000000.50000001}""", false)]
    [InlineData("""{"exp":1700000000.49}""", false)]
    [InlineData("""{"exp":1700000001,"nbf":1700000000.51}""", false)]
    [InlineData("""{"exp":1700000001,"iat":1700000000.51}""", false)]
    [InlineData("""{"exp":1e400}""", false)]
    [InlineData("""{"exp":253402300800.5}""", false)]
    [InlineData("""{"exp":-62135596800.5}""", false)]
    public void Should_ValidateFractionalJwtNumericDatesPrecisely(string payloadJson, bool expected)
    {
        using var payload = JsonDocument.Parse(payloadJson);
        var options = new SdJwtVerificationOptions { ClockSkew = TimeSpan.Zero };

        var valid = new ClaimValidator().ValidateTemporalClaims(payload.RootElement, options, _fixedNow);

        Assert.Equal(expected, valid);
    }

    [Fact]
    public void Should_InterpretNegativeFractionalUnixSecondsWithoutRoundingForward()
    {
        using var payload = JsonDocument.Parse(
            """{"exp":-0.25,"nbf":-1.5,"iat":-1.5}""");
        var now = DateTimeOffset.FromUnixTimeSeconds(-1).AddMilliseconds(500);

        Assert.True(new ClaimValidator().ValidateTemporalClaims(
            payload.RootElement,
            new SdJwtVerificationOptions { ClockSkew = TimeSpan.Zero },
            now));
    }

    [Theory]
    [InlineData("1700000000.25", true)]
    [InlineData("1699999700.50", true)]
    [InlineData("1699999700.49", false)]
    [InlineData("1700000060.50", true)]
    [InlineData("1699999700.49999999", false)]
    [InlineData("1700000060.50000001", false)]
    [InlineData("1700000060.51", false)]
    [InlineData("1e400", false)]
    [InlineData("253402300800.5", false)]
    public void Should_VerifySignedFractionalKeyBindingIatWithExactFreshness(string iat, bool expected)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var header = Base64UrlEncoder.Encode("""{"alg":"ES256","typ":"kb+jwt"}""");
        var payloadJson = "{\"sd_hash\":\"hash\",\"aud\":\"aud\",\"nonce\":\"nonce\",\"iat\":" + iat + "}";
        var payload = Base64UrlEncoder.Encode(payloadJson);
        var signingInput = $"{header}.{payload}";
        var signingBytes = System.Text.Encoding.UTF8.GetBytes(signingInput);
        var signature = holder.SignData(signingBytes, HashAlgorithmName.SHA256);

        // A real P-256 signature: any rejection below is numeric-date validation.
        Assert.True(holder.VerifyData(signingBytes, signature, HashAlgorithmName.SHA256));
        var proof = $"{signingInput}.{Base64UrlEncoder.Encode(signature)}";

        Assert.Equal(expected, new KeyBindingValidator(new FixedTimeProvider(_fixedNow))
            .ValidateKeyBinding(proof, holder.ExportSubjectPublicKeyInfo(), "hash", "aud", "nonce"));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
