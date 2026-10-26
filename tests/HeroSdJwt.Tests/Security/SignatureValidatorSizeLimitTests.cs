using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Standalone signature validation must enforce the JWT size limit even when
/// invoked outside the SD-JWT presentation verifier.
/// </summary>
public class SignatureValidatorSizeLimitTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public void Should_RejectOversizedCorrectlySignedJwtWithoutCallingKeyResolver()
    {
        var jwt = CreateSignedJwt(new string('x', 50_000));
        Assert.True(jwt.Length > Constants.MAX_JWT_SIZE_BYTES);

        // The HMAC really matches; this must be rejected for its size rather
        // than due to a malformed signature or unsupported algorithm.
        var segments = jwt.Split('.');
        Assert.Equal(3, segments.Length);
        var signedInput = Encoding.UTF8.GetBytes(segments[0] + "." + segments[1]);
        Assert.Equal(Base64UrlEncoder.Encode(HMACSHA256.HashData(_signingKey, signedInput)), segments[2]);

        var validator = new SignatureValidator();
        var direct = Assert.Throws<SdJwtException>(() => validator.VerifyJwtSignature(jwt, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, direct.ErrorCode);

        var resolverCalls = 0;
        byte[]? Resolve(string keyId)
        {
            resolverCalls++;
            return keyId == "signature-size-test-key" ? _signingKey : null;
        }

        var resolved = Assert.Throws<SdJwtException>(() => validator.VerifyJwtSignature(jwt, Resolve));
        Assert.Equal(ErrorCode.InvalidInput, resolved.ErrorCode);
        Assert.Equal(0, resolverCalls);
    }

    [Fact]
    public void Should_ContinueAcceptingValidJwtWithinSizeLimit()
    {
        var jwt = CreateSignedJwt("ordinary payload");
        Assert.True(jwt.Length <= Constants.MAX_JWT_SIZE_BYTES);

        var validator = new SignatureValidator();
        Assert.True(validator.VerifyJwtSignature(jwt, _signingKey));
        Assert.True(validator.VerifyJwtSignature(
            jwt, keyId => keyId == "signature-size-test-key" ? _signingKey : null));
    }

    [Fact]
    public void Should_RejectExtraDotSeparatedPartsBeforeResolvingKey()
    {
        var jwt = CreateSignedJwt("ordinary payload") + ".unexpected";
        var resolverCalls = 0;
        byte[]? Resolve(string _)
        {
            resolverCalls++;
            return _signingKey;
        }

        var validator = new SignatureValidator();
        var direct = Assert.Throws<SdJwtException>(() => validator.VerifyJwtSignature(jwt, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, direct.ErrorCode);
        var resolved = Assert.Throws<SdJwtException>(() => validator.VerifyJwtSignature(jwt, Resolve));
        Assert.Equal(ErrorCode.InvalidInput, resolved.ErrorCode);
        Assert.Equal(0, resolverCalls);
    }

    private static string CreateSignedJwt(string data)
    {
        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"signature-size-test-key\"}";
        var payload = JsonSerializer.Serialize(new { data });
        var signingInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_signingKey, Encoding.UTF8.GetBytes(signingInput));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }
}
