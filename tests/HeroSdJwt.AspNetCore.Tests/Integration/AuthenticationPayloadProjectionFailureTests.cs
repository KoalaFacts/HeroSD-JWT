using HeroSdJwt.AspNetCore.Authentication;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.AspNetCore.Tests.Integration;

/// <summary>
/// Even a custom verifier that reports success must not turn an unreadable issuer
/// payload into an authenticated principal with silently missing claims.
/// </summary>
public sealed class AuthenticationPayloadProjectionFailureTests
{
    [Theory]
    [InlineData("%%%")] // Not base64url
    [InlineData("W10")] // Valid base64url JSON array, not a JWT claims object
    public async Task Should_RejectUnmappablePayload_EvenWhenCustomVerifierReportsSuccess(string payload)
    {
        await using var provider = CreateServices();
        await using var scope = provider.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Headers.Authorization = $"Bearer header.{payload}.signature~";

        var result = await context.AuthenticateAsync("SdJwt");

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task Should_PreserveAuthentication_WhenCustomVerifierAcceptsReadableObjectPayload()
    {
        await using var provider = CreateServices();
        await using var scope = provider.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Headers.Authorization = "Bearer header.eyJzdWIiOiJob2xkZXItMSJ9.signature~";

        var result = await context.AuthenticateAsync("SdJwt");

        Assert.True(result.Succeeded);
        Assert.Equal("holder-1", result.Principal?.FindFirst("sub")?.Value);
    }

    private static ServiceProvider CreateServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSdJwtServices();
        services.AddSingleton<ISdJwtVerifier>(new PermissiveTestVerifier());
        services.AddAuthentication().AddSdJwt(options =>
        {
            options.FallbackKey = new byte[32];
            options.VerificationOptions = new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Symmetric
            };
        });

        return services.BuildServiceProvider();
    }

    private sealed class PermissiveTestVerifier : ISdJwtVerifier, ISdJwtVerifierFactory
    {
        public ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions options) => this;

        private static VerificationResult ValidResult() =>
            new(new Dictionary<string, JsonElement>());

        public VerificationResult TryVerifyPresentation(
            string presentation, byte[] publicKey, HashAlgorithm? expectedHashAlgorithm = null) => ValidResult();

        public VerificationResult TryVerifyPresentation(
            string presentation, KeyResolver? keyResolver, byte[]? fallbackKey = null,
            HashAlgorithm? expectedHashAlgorithm = null) => ValidResult();

        public VerificationResult VerifyPresentation(
            string presentation, byte[] publicKey, HashAlgorithm? expectedHashAlgorithm = null) => ValidResult();

        public VerificationResult VerifyPresentation(
            string presentation, KeyResolver? keyResolver, byte[]? fallbackKey = null,
            HashAlgorithm? expectedHashAlgorithm = null) => ValidResult();
    }
}
