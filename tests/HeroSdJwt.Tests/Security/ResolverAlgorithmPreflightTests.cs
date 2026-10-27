using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// An unauthenticated JOSE algorithm cannot cause an unnecessary call to an
/// application key resolver (which may use a remote service).
/// </summary>
public class ResolverAlgorithmPreflightTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("none")]
    [InlineData("NoNe")]
    [InlineData("RS256")]
    [InlineData("ES256")]
    public async Task Should_RejectAlgorithmConfusionBeforeKeyResolution(string algorithm)
    {
        var presentation = SignJwt(algorithm) + "~";
        var resolverCalls = 0;
        byte[]? Resolver(string _)
        {
            resolverCalls++;
            return _signingKey;
        }

        var verifier = CreateVerifier();
        var result = verifier.TryVerifyPresentation(presentation, Resolver);
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.AlgorithmConfusion, result.Errors);
        Assert.Equal(0, resolverCalls);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, Resolver, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.AlgorithmConfusion, asyncResult.Errors);
        Assert.Equal(0, resolverCalls);

        var exception = Assert.ThrowsAny<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, Resolver));
        Assert.Equal(ErrorCode.AlgorithmConfusion, exception.ErrorCode);
        Assert.Equal(0, resolverCalls);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("NoNe")]
    public void Should_RejectNoneBeforeStandaloneSignatureKeyResolution(string algorithm)
    {
        var resolverCalls = 0;
        byte[]? Resolver(string _)
        {
            resolverCalls++;
            return _signingKey;
        }

        _ = Assert.Throws<AlgorithmConfusionException>(() =>
            new SignatureValidator().VerifyJwtSignature(SignJwt(algorithm), Resolver));
        Assert.Equal(0, resolverCalls);
    }

    [Theory]
    [InlineData("unknown-signature")]
    [InlineData("")]
    public void Should_RejectUnsupportedAlgorithmBeforeStandaloneSignatureKeyResolution(string algorithm)
    {
        var resolverCalls = 0;
        byte[]? Resolver(string _)
        {
            resolverCalls++;
            return _signingKey;
        }

        var signatureValidator = new SignatureValidator();
        if (algorithm.Length == 0)
        {
            var exception = Assert.Throws<SdJwtException>(() =>
                signatureValidator.VerifyJwtSignature(SignJwt(algorithm), Resolver));
            Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
        }
        else
        {
            _ = Assert.Throws<AlgorithmNotSupportedException>(() =>
                signatureValidator.VerifyJwtSignature(SignJwt(algorithm), Resolver));
        }

        Assert.Equal(0, resolverCalls);
    }

    [Fact]
    public async Task Should_StillResolveSupportedSignedJwt()
    {
        var jwt = SignJwt("HS256");
        var resolverCalls = 0;
        byte[]? Resolver(string kid)
        {
            resolverCalls++;
            return kid == "preflight-key" ? _signingKey : null;
        }

        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, Resolver));
        Assert.Equal(1, resolverCalls);

        var verifier = CreateVerifier();
        var result = await verifier.TryVerifyPresentationAsync(
            jwt + "~", Resolver, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.Equal(2, resolverCalls);
    }

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static string SignJwt(string algorithm)
    {
        var header = "{\"alg\":\"" + algorithm + "\",\"kid\":\"preflight-key\"}";
        const string payload = /*lang=json,strict*/ "{\"exp\":4102444800}";
        var signingInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(signingInput));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }
}
