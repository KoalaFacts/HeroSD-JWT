using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 7515 JOSE Header Parameter names must be unambiguous.
/// A valid cryptographic signature does not make duplicate parameters safe.
/// </summary>
public class DuplicateJoseHeaderNamesTests
{
    private static readonly byte[] _issuerKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("alg", "none", "HS256")]
    [InlineData("kid", "other-key", "key-1")]
    [InlineData("typ", "unexpected", "JWT")]
    [InlineData("cty", "first", "second")]
    [InlineData("extension", "first", "second")]
    [InlineData("escaped-alg", "HS256", "HS256")]
    public async Task Should_RejectGenuinelySignedJwtWithDuplicateProtectedHeaderNames(
        string name, string first, string second)
    {
        var memberName = name == "escaped-alg" ? "\\u0061lg" : name;
        var headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"key-1\",\"" +
            memberName + "\":" + JsonSerializer.Serialize(first) + ",\"" +
            memberName + "\":" + JsonSerializer.Serialize(second) + "}";
        var jwt = SignIssuerJwt(headerJson);

        var parts = jwt.Split('.');
        var signedInput = System.Text.Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
        Assert.Equal(
            Base64UrlEncoder.Encode(HMACSHA256.HashData(_issuerKey, signedInput)),
            parts[2]);

        var resolverCalls = 0;
        byte[]? Resolver(string _)
        {
            resolverCalls++;
            return _issuerKey;
        }

        var validator = new SignatureValidator();
        var directError = Assert.Throws<SdJwtException>(() =>
            validator.VerifyJwtSignature(jwt, _issuerKey));
        Assert.Equal(ErrorCode.InvalidInput, directError.ErrorCode);
        var resolverError = Assert.Throws<SdJwtException>(() =>
            validator.VerifyJwtSignature(jwt, Resolver));
        Assert.Equal(ErrorCode.InvalidInput, resolverError.ErrorCode);

        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });

        var direct = verifier.TryVerifyPresentation(jwt + "~", _issuerKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(jwt + "~", Resolver);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            jwt + "~", Resolver, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);

        Assert.Equal(0, resolverCalls);
    }

    [Theory]
    [InlineData("alg", "ES256", "ES256")]
    [InlineData("typ", "kb+jwt", "kb+jwt")]
    [InlineData("kid", "first", "second")]
    [InlineData("extension", "first", "second")]
    [InlineData("escaped-alg", "ES256", "ES256")]
    public void Should_RejectGenuinelySignedKeyBindingWithDuplicateHeaderNames(
        string name, string first, string second)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var memberName = name == "escaped-alg" ? "\\u0061lg" : name;
        var headerJson = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\",\"" +
            memberName + "\":" + JsonSerializer.Serialize(first) + ",\"" +
            memberName + "\":" + JsonSerializer.Serialize(second) + "}";

        var proof = SignKeyBindingJwt(holder, headerJson);
        Assert.False(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), "signed-hash", "audience", "nonce"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectMalformedUnicodeMemberNameInIssuerHeaderWithoutEscapingException(
        bool manyParameters)
    {
        var prefix = manyParameters
            ? string.Join(",", Enumerable.Range(0, 9).Select(i => "\"extension-" + i + "\":true")) + ","
            : string.Empty;
        // The JSON parser accepts an escaped unpaired high surrogate, but
        // decoding that property name must never escape a validation API.
        var headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"key-1\"," +
            prefix + "\"x\\uD800\":0}";
        var jwt = SignIssuerJwt(headerJson);

        var error = Assert.Throws<SdJwtException>(() =>
            new SignatureValidator().VerifyJwtSignature(jwt, _issuerKey));
        Assert.Equal(ErrorCode.InvalidInput, error.ErrorCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectMalformedUnicodeMemberNameInKeyBindingWithoutThrowing(
        bool manyParameters)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var prefix = manyParameters
            ? string.Join(",", Enumerable.Range(0, 9).Select(i => "\"extension-" + i + "\":true")) + ","
            : string.Empty;
        var headerJson = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"," +
            prefix + "\"x\\uD800\":0}";
        var proof = SignKeyBindingJwt(holder, headerJson);

        Assert.False(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), "signed-hash", "audience", "nonce"));
    }

    [Fact]
    public void Should_AllowSignedUniqueNoncriticalExtensionOnBothJwtTypes()
    {
        var jwt = SignIssuerJwt(JsonSerializer.Serialize(new
        {
            alg = "HS256",
            typ = "JWT",
            kid = "key-1",
            extension = "safe"
        }));
        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, _issuerKey));

        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = SignKeyBindingJwt(holder, JsonSerializer.Serialize(new
        {
            alg = "ES256",
            typ = "kb+jwt",
            extension = "safe"
        }));
        Assert.True(new KeyBindingValidator().ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), "signed-hash", "audience", "nonce"));
    }

    private static string SignIssuerJwt(string headerJson)
    {
        var payload = new
        {
            iss = "https://issuer.example.test",
            sub = "user-123",
            exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            _sd_alg = "sha-256",
            _sd = Array.Empty<string>()
        };
        var input = Base64UrlEncoder.Encode(headerJson) + "." +
            Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload));
        var signature = HMACSHA256.HashData(
            _issuerKey, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }

    private static string SignKeyBindingJwt(ECDsa holder, string headerJson)
    {
        var payload = new
        {
            sd_hash = "signed-hash",
            aud = "audience",
            nonce = "nonce",
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };
        var input = Base64UrlEncoder.Encode(headerJson) + "." +
            Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload));
        var signedInput = System.Text.Encoding.UTF8.GetBytes(input);
        var signature = holder.SignData(signedInput, HashAlgorithmName.SHA256);
        Assert.True(holder.VerifyData(signedInput, signature, HashAlgorithmName.SHA256));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}
