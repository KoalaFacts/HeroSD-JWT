using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 7519 requires unique JWT Claim Names. Valid signatures must not
/// authenticate ambiguous issuer or key-binding payloads.
/// </summary>
public class DuplicateJwtClaimNamesTests
{
    private static readonly byte[] _issuerKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("exp")]
    [InlineData("_sd_alg")]
    [InlineData("aud")]
    [InlineData("extension")]
    [InlineData("escaped-exp")]
    public async Task Should_RejectSignedIssuerJwtWithDuplicateClaimNames(string claimName)
    {
        var expires = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var memberName = claimName == "escaped-exp" ? "\\u0065xp" : claimName;
        var memberValue = claimName switch
        {
            "exp" or "escaped-exp" => expires.ToString(CultureInfo.InvariantCulture),
            "_sd_alg" => JsonSerializer.Serialize("sha-256"),
            _ => JsonSerializer.Serialize("safe")
        };
        var payloadJson = $"{{\"exp\":{expires},\"_sd\":[],\"_sd_alg\":\"sha-256\"," +
            $"\"{memberName}\":{memberValue},\"{memberName}\":{memberValue}}}";

        await AssertIssuerRejectedAsync(payloadJson);
    }

    [Fact]
    public async Task Should_RejectDuplicateIssuerClaimWithManyOtherClaims()
    {
        var expires = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var extraMembers = string.Join(",", Enumerable.Range(0, 9).Select(i => $"\"ext-{i}\":true"));
        var payloadJson = $"{{\"exp\":{expires},\"_sd\":[],\"_sd_alg\":\"sha-256\"," +
            extraMembers + ",\"repeated\":\"one\",\"repeated\":\"two\"}";

        await AssertIssuerRejectedAsync(payloadJson);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_RejectMalformedUnicodeClaimNameWithoutLeakingException(bool manyMembers)
    {
        var expires = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var extraMembers = manyMembers
            ? string.Join(",", Enumerable.Range(0, 9).Select(i => $"\"ext-{i}\":true")) + ","
            : string.Empty;
        var payloadJson = $"{{\"exp\":{expires},\"_sd\":[],\"_sd_alg\":\"sha-256\"," +
            extraMembers + "\"x\\uD800\":true}";

        await AssertIssuerRejectedAsync(payloadJson);
    }

    [Theory]
    [InlineData("sd_hash")]
    [InlineData("aud")]
    [InlineData("nonce")]
    [InlineData("iat")]
    [InlineData("extension")]
    [InlineData("escaped-aud")]
    public void Should_RejectSignedKeyBindingJwtWithDuplicateClaimNames(string claimName)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var memberName = claimName == "escaped-aud" ? "\\u0061ud" : claimName;
        var memberValue = claimName switch
        {
            "iat" => issuedAt.ToString(CultureInfo.InvariantCulture),
            "sd_hash" => JsonSerializer.Serialize("signed-hash"),
            "aud" or "escaped-aud" => JsonSerializer.Serialize("audience"),
            "nonce" => JsonSerializer.Serialize("nonce"),
            _ => JsonSerializer.Serialize("safe")
        };
        var payloadJson = $"{{\"sd_hash\":\"signed-hash\",\"aud\":\"audience\"," +
            $"\"nonce\":\"nonce\",\"iat\":{issuedAt}," +
            $"\"{memberName}\":{memberValue},\"{memberName}\":{memberValue}}}";
        var proof = SignKeyBindingJwt(holder, payloadJson);

        Assert.False(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), "signed-hash", "audience", "nonce"));
    }

    [Fact]
    public void Should_RejectDuplicateKeyBindingClaimWithManyOtherClaims()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var extraMembers = string.Join(",", Enumerable.Range(0, 9).Select(i => $"\"ext-{i}\":true"));
        var payloadJson = $"{{\"sd_hash\":\"signed-hash\",\"aud\":\"audience\"," +
            $"\"nonce\":\"nonce\",\"iat\":{issuedAt}," +
            extraMembers + ",\"repeated\":\"one\",\"repeated\":\"two\"}";
        var proof = SignKeyBindingJwt(holder, payloadJson);

        Assert.False(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), "signed-hash", "audience", "nonce"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectMalformedUnicodeKeyBindingClaimWithoutThrowing(bool manyMembers)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var extraMembers = manyMembers
            ? string.Join(",", Enumerable.Range(0, 9).Select(i => $"\"ext-{i}\":true")) + ","
            : string.Empty;
        var payloadJson = $"{{\"sd_hash\":\"signed-hash\",\"aud\":\"audience\"," +
            $"\"nonce\":\"nonce\",\"iat\":{issuedAt}," +
            extraMembers + "\"x\\uD800\":true}";
        var proof = SignKeyBindingJwt(holder, payloadJson);

        Assert.False(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), "signed-hash", "audience", "nonce"));
    }

    [Fact]
    public void Should_AcceptSignedIssuerAndKeyBindingWithUniqueExtensionClaims()
    {
        var expires = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var payloadJson = JsonSerializer.Serialize(new
        {
            exp = expires,
            _sd = Array.Empty<string>(),
            _sd_alg = "sha-256",
            extension = "safe"
        });
        var jwt = SignIssuerJwt(payloadJson);
        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });
        Assert.True(verifier.TryVerifyPresentation(jwt + "~", _issuerKey).IsValid);

        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = SignKeyBindingJwt(holder, JsonSerializer.Serialize(new
        {
            sd_hash = "signed-hash",
            aud = "audience",
            nonce = "nonce",
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            extension = "safe"
        }));
        Assert.True(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), "signed-hash", "audience", "nonce"));
    }

    private static async Task AssertIssuerRejectedAsync(string payloadJson)
    {
        var jwt = SignIssuerJwt(payloadJson);
        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, _issuerKey));
        var presentation = jwt + "~";
        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });

        var direct = verifier.TryVerifyPresentation(presentation, _issuerKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        static byte[]? Resolver(string id) => id == "key-1" ? _issuerKey : null;

        var resolved = verifier.TryVerifyPresentation(presentation, Resolver);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, Resolver, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);

        var thrown = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, _issuerKey));
        Assert.Equal(ErrorCode.InvalidInput, thrown.ErrorCode);
    }

    private static string SignIssuerJwt(string payloadJson)
    {
        const string headerJson = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"key-1\"}";
        var input = Base64UrlEncoder.Encode(headerJson) + "." +
            Base64UrlEncoder.Encode(payloadJson);
        var signature = HMACSHA256.HashData(
            _issuerKey, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }

    private static string SignKeyBindingJwt(ECDsa holder, string payloadJson)
    {
        const string headerJson = /*lang=json,strict*/ "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}";
        var input = Base64UrlEncoder.Encode(headerJson) + "." +
            Base64UrlEncoder.Encode(payloadJson);
        var signature = holder.SignData(
            System.Text.Encoding.UTF8.GetBytes(input), HashAlgorithmName.SHA256);
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}
