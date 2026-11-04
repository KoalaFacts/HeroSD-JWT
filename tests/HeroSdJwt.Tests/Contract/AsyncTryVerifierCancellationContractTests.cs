using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Contract;

public sealed class AsyncTryVerifierCancellationContractTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Repeat((byte)0x41, 32)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_PropagateCancellation_When_TryVerifyAsyncReceivesCanceledRequest(bool useResolver)
    {
        var presentation = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "cancel-contract")
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();
        ISdJwtVerifierAsync verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        using var request = new CancellationTokenSource();
        request.Cancel();

        Task<VerificationResult> Verify() => useResolver
            ? verifier.TryVerifyPresentationAsync(
                presentation,
                _ => _signingKey,
                cancellationToken: request.Token)
            : verifier.TryVerifyPresentationAsync(
                presentation,
                _signingKey,
                cancellationToken: request.Token);

        // A canceled request is not an invalid credential. ASP.NET Core must
        // observe cancellation even through the non-throwing Try* API.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(Verify);
    }
}
