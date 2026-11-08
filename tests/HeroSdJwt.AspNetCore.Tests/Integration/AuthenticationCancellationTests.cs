using HeroSdJwt.AspNetCore.Authentication;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.AspNetCore.Tests.Integration;

public sealed class AuthenticationCancellationTests
{
    [Fact]
    public async Task Should_PropagateCancellation_WhenRequestIsAborted()
    {
        var verifier = new CancelingVerifier();
        var services = CreateServices(verifier);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        using var aborted = new CancellationTokenSource();
        aborted.Cancel();

        var context = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
            RequestAborted = aborted.Token
        };
        context.Request.Headers.Authorization = "Bearer header.payload.signature~";

        // A canceled HTTP request is not an authentication failure. Do not
        // swallow the cancellation or report it as a failed credential.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => context.AuthenticateAsync("SdJwt"));

        // A verifier factory may call remote KMS or database services. An
        // already-aborted request must not invoke the factory at all.
        Assert.Equal(0, verifier.FactoryCalls);
    }

    [Fact]
    public async Task Should_FailClosed_WhenVerifierCancelsAnActiveRequest()
    {
        var services = CreateServices();
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Headers.Authorization = "Bearer header.payload.signature~";

        // An unexpected provider cancellation is not permission to authenticate.
        var result = await context.AuthenticateAsync("SdJwt");

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
    }

    private static ServiceCollection CreateServices(CancelingVerifier? verifier = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISdJwtVerifier>(verifier ?? new CancelingVerifier());
        services.AddAuthentication().AddSdJwt(options =>
        {
            options.FallbackKey = new byte[32];
        });
        return services;
    }

    private sealed class CancelingVerifier : ISdJwtVerifier, ISdJwtVerifierAsync, ISdJwtVerifierFactory
    {
        public int FactoryCalls { get; private set; }

        public ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions options)
        {
            FactoryCalls++;
            return this;
        }

        private static Task<VerificationResult> Canceled() =>
            Task.FromCanceled<VerificationResult>(new CancellationToken(canceled: true));

        public Task<VerificationResult> TryVerifyPresentationAsync(
            string presentation,
            byte[] publicKey,
            HashAlgorithm? expectedHashAlgorithm = null,
            CancellationToken cancellationToken = default) => Canceled();

        public Task<VerificationResult> TryVerifyPresentationAsync(
            string presentation,
            KeyResolver? keyResolver,
            byte[]? fallbackKey = null,
            HashAlgorithm? expectedHashAlgorithm = null,
            CancellationToken cancellationToken = default) => Canceled();

        public Task<VerificationResult> VerifyPresentationAsync(
            string presentation,
            byte[] publicKey,
            HashAlgorithm? expectedHashAlgorithm = null,
            CancellationToken cancellationToken = default) => Canceled();

        public Task<VerificationResult> VerifyPresentationAsync(
            string presentation,
            KeyResolver? keyResolver,
            byte[]? fallbackKey = null,
            HashAlgorithm? expectedHashAlgorithm = null,
            CancellationToken cancellationToken = default) => Canceled();

        public VerificationResult TryVerifyPresentation(
            string presentation,
            byte[] publicKey,
            HashAlgorithm? expectedHashAlgorithm = null) => throw new NotSupportedException();

        public VerificationResult TryVerifyPresentation(
            string presentation,
            KeyResolver? keyResolver,
            byte[]? fallbackKey = null,
            HashAlgorithm? expectedHashAlgorithm = null) => throw new NotSupportedException();

        public VerificationResult VerifyPresentation(
            string presentation,
            byte[] publicKey,
            HashAlgorithm? expectedHashAlgorithm = null) => throw new NotSupportedException();

        public VerificationResult VerifyPresentation(
            string presentation,
            KeyResolver? keyResolver,
            byte[]? fallbackKey = null,
            HashAlgorithm? expectedHashAlgorithm = null) => throw new NotSupportedException();
    }
}
