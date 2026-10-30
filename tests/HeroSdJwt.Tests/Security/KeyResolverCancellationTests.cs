using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A canceled key-resolution operation must not be converted into a malformed
/// credential or a key lookup failure by the throwing verification API.
/// </summary>
public class KeyResolverCancellationTests
{
    private const string KEY_ID = "cancellation-issuer-key";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public async Task Should_PropagatePreCanceledRequest_WithoutConsultingKeyResolver()
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cancellation.Cancel();

        var calls = 0;
        byte[]? resolver(string _)
        {
            calls++;
            return _signingKey;
        }
        var verifier = CreateVerifier();
        var presentation = CreatePresentation();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            verifier.VerifyPresentationAsync(
                presentation, resolver, cancellationToken: cancellation.Token));
        Assert.Equal(0, calls);

        // Try APIs return an invalid result on cancellation, never a valid token.
        var result = await verifier.TryVerifyPresentationAsync(
            presentation, resolver, cancellationToken: cancellation.Token);
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_PropagateCanceledKeyLookup_WithoutReportingKeyResolverFailed(
        bool cancelCaller)
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var calls = 0;
        byte[]? resolver(string _)
        {
            calls++;
            if (cancelCaller)
            {
                cancellation.Cancel();
            }

            // Key stores may independently time out even without caller cancellation.
            throw new OperationCanceledException("Key lookup canceled");
        }

        var verifier = CreateVerifier();
        var presentation = CreatePresentation();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            verifier.VerifyPresentationAsync(
                presentation, resolver, cancellationToken: cancellation.Token));
        Assert.Equal(1, calls);

        var result = await verifier.TryVerifyPresentationAsync(
            presentation, resolver, cancellationToken: cancellation.Token);
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);

        // Without a CancellationToken the synchronous throwing overload still
        // must not disguise a resolver's OperationCanceledException.
        if (!cancelCaller)
        {
            Assert.ThrowsAny<OperationCanceledException>(() =>
                verifier.VerifyPresentation(presentation, resolver));
        }
    }

    [Fact]
    public async Task Should_RedactBackendCancellationDetails_InTryVerificationResults()
    {
        const string backendDiagnostic = "kms-connection-secret=do-not-disclose";
        var verifier = CreateVerifier();
        var presentation = CreatePresentation();

        byte[]? resolver(string _) => throw new OperationCanceledException(backendDiagnostic);

        var syncResult = verifier.TryVerifyPresentation(presentation, resolver);
        Assert.False(syncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, syncResult.Errors);
        Assert.DoesNotContain(backendDiagnostic, syncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, resolver, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResult.Errors);
        Assert.DoesNotContain(backendDiagnostic, asyncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
    }

    private static SdJwtVerifier CreateVerifier() =>
        TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });

    private static string CreatePresentation() =>
        SdJwtIssuerBuilder.Create()
            .WithKeyId(KEY_ID)
            .WithClaim("sub", "cancellation-user")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();
}
