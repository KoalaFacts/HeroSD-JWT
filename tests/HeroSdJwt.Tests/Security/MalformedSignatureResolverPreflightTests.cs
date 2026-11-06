using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A malformed compact JWS signature is not worth an external key lookup,
/// even when its encoded length matches the JOSE algorithm.
/// </summary>
public sealed class MalformedSignatureResolverPreflightTests
{
    private static readonly byte[] _issuerKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];
    private const string BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    [Theory]
    [InlineData("invalid-character")]
    [InlineData("padding")]
    [InlineData("nonzero-unused-bits")]
    public async Task Should_RejectMalformedSignatureBeforeKeyResolution(string corruption)
    {
        var jwt = SignJwt();
        var signatureStart = jwt.LastIndexOf('.') + 1;
        var signature = jwt[signatureStart..];
        Assert.Equal(43, signature.Length);

        var invalidSignature = corruption switch
        {
            "invalid-character" => "!" + signature[1..],
            "padding" => signature[..^1] + "=",
            "nonzero-unused-bits" => signature[..^1] +
                BASE64URL_ALPHABET[BASE64URL_ALPHABET.IndexOf(signature[^1]) + 1],
            _ => throw new ArgumentOutOfRangeException(nameof(corruption))
        };

        Assert.Equal(signature.Length, invalidSignature.Length);
        var invalidJwt = jwt[..signatureStart] + invalidSignature;
        var resolverCalls = 0;
        byte[]? Resolve(string keyId)
        {
            resolverCalls++;
            return keyId == "signature-preflight-key" ? _issuerKey : null;
        }

        // A direct caller should receive its existing InvalidInput domain
        // failure without the invalid signature invoking a remote resolver.
        var domainError = Assert.Throws<SdJwtException>(() =>
            new SignatureValidator().VerifyJwtSignature(invalidJwt, Resolve));
        Assert.Equal(ErrorCode.InvalidInput, domainError.ErrorCode);
        Assert.Equal(0, resolverCalls);

        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        var sync = verifier.TryVerifyPresentation(invalidJwt + "~", Resolve);
        Assert.False(sync.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, sync.Errors);
        Assert.Equal(0, resolverCalls);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            invalidJwt + "~", Resolve, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResult.Errors);
        Assert.Equal(0, resolverCalls);
    }

    [Theory]
    [InlineData("invalid-character")]
    [InlineData("padding")]
    [InlineData("nonzero-unused-bits")]
    [InlineData("invalid-length")]
    [InlineData("empty")]
    public async Task Should_RejectMalformedPayloadBeforeKeyResolution(string corruption)
    {
        // The two-sextet tail permits a noncanonical encoding with unchanged length.
        var jwt = SignJwt(/*lang=json,strict*/ """{"exp":4102444800,"sub":"a"}""");
        var payloadStart = jwt.IndexOf('.') + 1;
        var payloadEnd = jwt.IndexOf('.', payloadStart);
        var payload = jwt[payloadStart..payloadEnd];
        Assert.Equal(2, payload.Length % 4);

        var invalidPayload = corruption switch
        {
            "invalid-character" => "!" + payload[1..],
            "padding" => payload[..^1] + "=",
            "nonzero-unused-bits" => payload[..^1] +
                BASE64URL_ALPHABET[BASE64URL_ALPHABET.IndexOf(payload[^1]) + 1],
            "invalid-length" => payload[..^1],
            "empty" => string.Empty,
            _ => throw new ArgumentOutOfRangeException(nameof(corruption))
        };
        var invalidJwt = jwt[..payloadStart] + invalidPayload + jwt[payloadEnd..];

        var resolverCalls = 0;
        byte[]? Resolve(string _)
        {
            resolverCalls++;
            return _issuerKey;
        }

        var standaloneError = Assert.Throws<SdJwtException>(() =>
            new SignatureValidator().VerifyJwtSignature(invalidJwt, Resolve));
        Assert.Equal(ErrorCode.InvalidInput, standaloneError.ErrorCode);
        Assert.Equal(0, resolverCalls);

        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        var sync = verifier.TryVerifyPresentation(invalidJwt + "~", Resolve);
        Assert.False(sync.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, sync.Errors);
        Assert.Equal(0, resolverCalls);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            invalidJwt + "~", Resolve, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResult.Errors);
        Assert.Equal(0, resolverCalls);
    }

    [Fact]
    public async Task Should_ResolveOneKeyForWellFormedSignedJwt()
    {
        var jwt = SignJwt();
        var resolverCalls = 0;
        byte[]? Resolve(string keyId)
        {
            resolverCalls++;
            return keyId == "signature-preflight-key" ? _issuerKey : null;
        }

        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, Resolve));
        Assert.Equal(1, resolverCalls);

        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();
        var result = await verifier.TryVerifyPresentationAsync(
            jwt + "~", Resolve, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.Equal(2, resolverCalls);
    }

    private static string SignJwt(string payload = /*lang=json,strict*/ """{"exp":4102444800}""")
    {
        const string header = /*lang=json,strict*/ """{"alg":"HS256","kid":"signature-preflight-key"}""";
        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_issuerKey, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}
