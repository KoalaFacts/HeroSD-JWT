using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Malformed separator floods must not allocate a position buffer proportional
/// to every delimiter before the bounded token/presentation parser rejects them.
/// </summary>
public class BoundedSeparatorAllocationTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public void Should_RejectDotFloodWithoutProportionalAllocationsOrKeyResolution()
    {
        var jwt = Base64UrlEncoder.Encode(/*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"flood-key\"}")
            + "." + new string('.', 55_000) + ".signature";
        var presentation = jwt + "~";
        Assert.True(jwt.Length < Constants.MAX_JWT_SIZE_BYTES);
        var resolverCalls = 0;
        byte[]? Resolve(string _)
        {
            resolverCalls++;
            return _signingKey;
        }

        var validator = new SignatureValidator();
        var verifier = CreateVerifier();

        var directAllocations = MeasureAllocatedBytes(() =>
        {
            var ex = Assert.Throws<SdJwtException>(() => validator.VerifyJwtSignature(jwt, _signingKey));
            Assert.Equal(ErrorCode.InvalidInput, ex.ErrorCode);
        });
        var resolvedAllocations = MeasureAllocatedBytes(() =>
        {
            var ex = Assert.Throws<SdJwtException>(() => validator.VerifyJwtSignature(jwt, Resolve));
            Assert.Equal(ErrorCode.InvalidInput, ex.ErrorCode);
        });
        var presentationAllocations = MeasureAllocatedBytes(() =>
        {
            var result = verifier.TryVerifyPresentation(presentation, _signingKey);
            Assert.False(result.IsValid);
            Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        });
        var resolvedPresentationAllocations = MeasureAllocatedBytes(() =>
        {
            var result = verifier.TryVerifyPresentation(presentation, Resolve);
            Assert.False(result.IsValid);
            Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        });

        Assert.Equal(0, resolverCalls);
        Assert.True(directAllocations < 1_000_000, $"Standalone direct verification allocated {directAllocations} bytes");
        Assert.True(resolvedAllocations < 1_000_000, $"Standalone resolved verification allocated {resolvedAllocations} bytes");
        Assert.True(presentationAllocations < 1_000_000, $"Presentation verification allocated {presentationAllocations} bytes");
        Assert.True(resolvedPresentationAllocations < 1_000_000, $"Resolved presentation verification allocated {resolvedPresentationAllocations} bytes");
    }

    [Fact]
    public async Task Should_RejectTildeFloodBeforeKeyResolutionWithoutProportionalAllocations()
    {
        var presentation = CreateSignedJwt() + "~" + new string('~', 55_000);
        Assert.True(presentation.Length < Constants.MAX_JWT_SIZE_BYTES);
        var verifier = CreateVerifier();
        var resolverCalls = 0;
        byte[]? Resolve(string _)
        {
            resolverCalls++;
            return _signingKey;
        }

        var directAllocations = MeasureAllocatedBytes(() =>
        {
            var result = verifier.TryVerifyPresentation(presentation, _signingKey);
            Assert.False(result.IsValid);
            Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        });
        var resolvedAllocations = MeasureAllocatedBytes(() =>
        {
            var result = verifier.TryVerifyPresentation(presentation, Resolve);
            Assert.False(result.IsValid);
            Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        });

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, Resolve, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);
        Assert.Equal(0, resolverCalls);
        Assert.True(directAllocations < 1_000_000, $"Tilde flood allocated {directAllocations} bytes");
        Assert.True(resolvedAllocations < 1_000_000, $"Resolved tilde flood allocated {resolvedAllocations} bytes");
    }

    [Fact]
    public async Task Should_ContinueAcceptingSignedCompactJwtAndEmptyDisclosurePresentation()
    {
        var jwt = CreateSignedJwt();
        var validator = new SignatureValidator();
        Assert.True(validator.VerifyJwtSignature(jwt, _signingKey));
        Assert.True(validator.VerifyJwtSignature(jwt, Resolve));

        var verifier = CreateVerifier();
        var presentation = jwt + "~";
        Assert.True(verifier.TryVerifyPresentation(presentation, _signingKey).IsValid);
        Assert.True(verifier.TryVerifyPresentation(presentation, Resolve).IsValid);
        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncResult.IsValid, asyncResult.ErrorDetails);
    }

    private static long MeasureAllocatedBytes(Action action)
    {
        action(); // Warm up the JIT and expected exception/verification paths.
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < 12; i++)
        {
            action();
        }

        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static byte[]? Resolve(string keyId) =>
        keyId == "flood-key" ? _signingKey : null;

    private static string CreateSignedJwt()
    {
        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"flood-key\"}";
        const string payload = /*lang=json,strict*/ "{\"exp\":4102444800}";
        var signingInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(signingInput));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }
}
