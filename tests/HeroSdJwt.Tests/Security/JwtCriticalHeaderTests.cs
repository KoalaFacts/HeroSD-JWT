using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A cryptographically correct signature must not bypass unsupported
/// protected-header semantics on either direct or key-resolver APIs.
/// </summary>
public class JwtCriticalHeaderTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("unknown-critical")]
    [InlineData("b64-critical")]
    [InlineData("empty-critical")]
    [InlineData("scalar-critical")]
    [InlineData("null-critical")]
    [InlineData("b64-without-critical")]
    public void Should_RejectSignedJwtWithUnsupportedJoseHeader(string mutation)
    {
        var header = NewHeader();
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

        var jwt = Sign(header);
        var parts = jwt.Split('.');
        using (var hmac = new HMACSHA256(_signingKey))
        {
            var input = System.Text.Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
            Assert.Equal(Base64UrlEncoder.Encode(hmac.ComputeHash(input)), parts[2]);
        }

        var signatureValidator = new SignatureValidator();
        var directException = Assert.Throws<SdJwtException>(() =>
            signatureValidator.VerifyJwtSignature(jwt, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, directException.ErrorCode);

        static byte[]? Resolver(string kid)
        {
            return kid == "key-1" ? _signingKey : null;
        }
        var resolverException = Assert.Throws<SdJwtException>(() =>
            signatureValidator.VerifyJwtSignature(jwt, Resolver));
        Assert.Equal(ErrorCode.InvalidInput, resolverException.ErrorCode);

        var verifier = CreateVerifier();
        var direct = verifier.TryVerifyPresentation(jwt + "~", _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(jwt + "~", Resolver);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("42")]
    [InlineData("[]")]
    [InlineData("{}")]
    public async Task Should_RejectSignedJwtWithNonStringKidInsteadOfUsingFallback(string kidJson)
    {
        var header = NewHeader();
        header["kid"] = JsonSerializer.Deserialize<JsonElement>(kidJson);
        var jwt = Sign(header);
        var presentation = jwt + "~";

        // The JWT really is signed by the fallback key; a signature failure
        // must not conceal acceptance of an invalid JOSE header.
        var jwtParts = jwt.Split('.');
        var expectedSignature = HMACSHA256.HashData(
            _signingKey,
            System.Text.Encoding.UTF8.GetBytes(jwtParts[0] + "." + jwtParts[1]));
        Assert.Equal(Base64UrlEncoder.Encode(expectedSignature), jwtParts[2]);

        var resolverCalls = 0;
        byte[]? Resolver(string _)
        {
            resolverCalls++;
            return _signingKey;
        }

        var signatureValidator = new SignatureValidator();
        var directException = Assert.Throws<SdJwtException>(() =>
            signatureValidator.VerifyJwtSignature(jwt, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, directException.ErrorCode);
        var resolvedException = Assert.Throws<SdJwtException>(() =>
            signatureValidator.VerifyJwtSignature(jwt, Resolver, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, resolvedException.ErrorCode);

        var verifier = CreateVerifier();
        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(presentation, Resolver, fallbackKey: _signingKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation,
            Resolver,
            fallbackKey: _signingKey,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);

        var verifyException = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, Resolver, fallbackKey: _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, verifyException.ErrorCode);
        Assert.Equal(0, resolverCalls);
    }

    [Fact]
    public void Should_UseFallbackOnlyWhenKeyIdIsAbsent()
    {
        var header = NewHeader();
        Assert.True(header.Remove("kid"));
        var jwt = Sign(header);
        var resolverCalls = 0;
        byte[]? Resolver(string _)
        {
            resolverCalls++;
            return null;
        }

        var signatureValidator = new SignatureValidator();
        Assert.True(signatureValidator.VerifyJwtSignature(jwt, Resolver, _signingKey));

        var verifier = CreateVerifier();
        var result = verifier.TryVerifyPresentation(jwt + "~", Resolver, fallbackKey: _signingKey);
        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.Equal(0, resolverCalls);
    }

    [Fact]
    public void Should_AcceptSignedJwtWithOrdinaryNoncriticalExtension()
    {
        var header = NewHeader();
        header["optional-extension"] = true;
        var jwt = Sign(header);

        var signatureValidator = new SignatureValidator();
        Assert.True(signatureValidator.VerifyJwtSignature(jwt, _signingKey));

        static byte[]? Resolver(string kid)
        {
            return kid == "key-1" ? _signingKey : null;
        }
        Assert.True(signatureValidator.VerifyJwtSignature(jwt, Resolver));

        var verifier = CreateVerifier();
        var direct = verifier.TryVerifyPresentation(jwt + "~", _signingKey);
        Assert.True(direct.IsValid, string.Join(", ", direct.Errors));

        var resolved = verifier.TryVerifyPresentation(jwt + "~", Resolver);
        Assert.True(resolved.IsValid, string.Join(", ", resolved.Errors));
    }

    private static SdJwtVerifier CreateVerifier()
    {
        return TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });
    }

    private static Dictionary<string, object?> NewHeader()
    {
        return new Dictionary<string, object?>
        {
            ["alg"] = "HS256",
            ["typ"] = "JWT",
            ["kid"] = "key-1"
        };
    }

    private static string Sign(Dictionary<string, object?> header)
    {
        var payload = new
        {
            iss = "https://issuer.example.test",
            sub = "user-123",
            exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            _sd_alg = "sha-256",
            _sd = Array.Empty<string>()
        };
        var signingInput = Base64UrlEncoder.Encode(JsonSerializer.Serialize(header)) + "." +
                           Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload));
        using var hmac = new HMACSHA256(_signingKey);
        return signingInput + "." + Base64UrlEncoder.Encode(hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signingInput)));
    }
}
