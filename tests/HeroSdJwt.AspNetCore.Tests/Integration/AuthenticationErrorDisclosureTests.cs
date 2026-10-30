using HeroSdJwt.AspNetCore.Authentication;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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

    private sealed class ProviderFailureVerifier(string diagnostic, bool failInFactory)
        : ISdJwtVerifier, ISdJwtVerifierFactory
    {
        public ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions options)
        {
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
