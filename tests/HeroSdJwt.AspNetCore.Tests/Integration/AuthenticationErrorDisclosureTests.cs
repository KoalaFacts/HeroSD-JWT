using HeroSdJwt.AspNetCore.Authentication;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.AspNetCore.Tests.Integration;

public class AuthenticationErrorDisclosureTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_NotExposeProviderDiagnostics_WhenAuthenticationFails(bool failInFactory)
    {
        // Application-supplied verifiers may return or throw messages containing
        // secrets from KMS/database providers. Neither authentication results
        // nor the handler's own log entries should publish those messages.
        const string sensitiveDiagnostic = "KMS-CREDENTIAL-DO-NOT-LOG";
        using var loggerProvider = new RecordingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(loggerProvider));
        services.AddSdJwtServices();
        services.AddSingleton<ISdJwtVerifier>(
            new ProviderFailureVerifier(sensitiveDiagnostic, failInFactory));
        services.AddAuthentication().AddSdJwt(options =>
        {
            options.FallbackKey = new byte[32];
            options.VerificationOptions = new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Symmetric
            };
        });

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Headers.Authorization = "Bearer header.payload.signature~";

        var result = await context.AuthenticateAsync("SdJwt");

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
        Assert.DoesNotContain(sensitiveDiagnostic, result.Failure.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(
            sensitiveDiagnostic,
            string.Join("\n", loggerProvider.Entries),
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_RejectOversizedPresentation_BeforeConsultingCustomVerifier(bool multibyte)
    {
        // A custom verifier may consult a KMS or another remote service.
        // Oversized wire inputs can never be valid and must be rejected by
        // the authentication boundary without invoking that factory.
        var verifier = new ProviderFailureVerifier("factory-should-not-run", failInFactory: true);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSdJwtServices();
        services.AddSingleton<ISdJwtVerifier>(verifier);
        services.AddAuthentication().AddSdJwt(options =>
        {
            options.FallbackKey = new byte[32];
            options.VerificationOptions = new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Symmetric
            };
        });

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        var oversizedToken = multibyte
            ? new string('é', Constants.MAX_JWT_SIZE_BYTES / 2 + 1)
            : new string('a', Constants.MAX_JWT_SIZE_BYTES + 1);
        context.Request.Headers.Authorization = "Bearer " + oversizedToken;

        var result = await context.AuthenticateAsync("SdJwt");

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
        Assert.Equal(0, verifier.FactoryCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_RejectAmbiguousAuthorization_BeforeCustomVerifierFactory(bool foldedHeader)
    {
        // Duplicate values and comma-folded Authorization headers are ambiguous.
        // Neither may be passed to a custom verifier that could access a remote KMS.
        var verifier = new ProviderFailureVerifier("factory-should-not-run", failInFactory: true);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSdJwtServices();
        services.AddSingleton<ISdJwtVerifier>(verifier);
        services.AddAuthentication().AddSdJwt(options =>
        {
            options.FallbackKey = new byte[32];
            options.VerificationOptions = new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Symmetric
            };
        });

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Headers.Authorization = foldedHeader
            ? new StringValues("Bearer header.payload.signature~, Bearer another.payload.signature~")
            : new StringValues(["Bearer header.payload.signature~", "Bearer another.payload.signature~"]);

        var result = await context.AuthenticateAsync("SdJwt");

        Assert.False(result.Succeeded);
        Assert.Equal(0, verifier.FactoryCalls);
    }

    private sealed class ProviderFailureVerifier(string diagnostic, bool failInFactory)
        : ISdJwtVerifier, ISdJwtVerifierFactory
    {
        public int FactoryCalls { get; private set; }

        public ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions options)
        {
            FactoryCalls++;
            if (failInFactory)
            {
                throw new InvalidOperationException(diagnostic);
            }

            return this;
        }

        public VerificationResult TryVerifyPresentation(
            string presentation, byte[] publicKey, HashAlgorithm? expectedHashAlgorithm = null)
            => new(ErrorCode.InvalidInput, diagnostic);

        public VerificationResult TryVerifyPresentation(
            string presentation, KeyResolver? keyResolver, byte[]? fallbackKey = null,
            HashAlgorithm? expectedHashAlgorithm = null)
            => new(ErrorCode.InvalidInput, diagnostic);

        public VerificationResult VerifyPresentation(
            string presentation, byte[] publicKey, HashAlgorithm? expectedHashAlgorithm = null)
            => throw new NotSupportedException();

        public VerificationResult VerifyPresentation(
            string presentation, KeyResolver? keyResolver, byte[]? fallbackKey = null,
            HashAlgorithm? expectedHashAlgorithm = null)
            => throw new NotSupportedException();
    }

    private sealed class RecordingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _entries = new();

        public IEnumerable<string> Entries => _entries;

        public ILogger CreateLogger(string categoryName) => new RecordingLogger(_entries);

        public void Dispose()
        {
        }

        private sealed class RecordingLogger(ConcurrentQueue<string> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                entries.Enqueue(formatter(state, exception));
                if (exception is not null)
                {
                    entries.Enqueue(exception.ToString());
                }
            }
        }
    }
}
