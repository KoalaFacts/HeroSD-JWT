using HeroSdJwt.Verification;
using System.Data.Common;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

public sealed class StorageFailureClassifierTests
{
    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, false)]
    [InlineData(HttpStatusCode.Forbidden, false)]
    [InlineData(HttpStatusCode.NotFound, false)]
    [InlineData(HttpStatusCode.RequestTimeout, true)]
    [InlineData(HttpStatusCode.TooManyRequests, true)]
    [InlineData(HttpStatusCode.InternalServerError, true)]
    [InlineData(HttpStatusCode.ServiceUnavailable, true)]
    public void Should_OnlyAllowHttpOutagesNotHttpConfigurationFailures(
        HttpStatusCode statusCode, bool isTransient)
    {
        var error = new HttpRequestException("backend diagnostic", inner: null, statusCode);
        Assert.Equal(isTransient, StorageFailureClassifier.IsTransient(error));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RespectDatabaseProviderTransientClassification(bool isTransient)
    {
        Assert.Equal(isTransient,
            StorageFailureClassifier.IsTransient(new ProviderDatabaseException(isTransient)));
    }

    [Fact]
    public void Should_AllowTransportFailuresWithoutHttpResponse()
    {
        Assert.True(StorageFailureClassifier.IsTransient(new IOException("backend offline")));
        Assert.True(StorageFailureClassifier.IsTransient(new TimeoutException("request expired")));
        Assert.True(StorageFailureClassifier.IsTransient(new HttpRequestException("connection reset")));
    }

    [Fact]
    public void Should_RejectAuthenticationAndAuthorizationFailuresWrappedByTransportErrors()
    {
        // A transport exception is not evidence of a temporary outage when
        // the underlying failure is TLS trust, access policy or cryptography.
        Exception[] errors =
        [
            new HttpRequestException("TLS certificate rejected",
                new AuthenticationException("untrusted certificate")),
            new HttpRequestException("storage credentials rejected",
                new UnauthorizedAccessException("access denied")),
            new IOException("secure channel failed",
                new SecurityException("permission denied")),
            new IOException("invalid protected payload",
                new CryptographicException("decryption failed"))
        ];

        foreach (var error in errors)
        {
            Assert.False(StorageFailureClassifier.IsTransient(error));
        }
    }

    [Fact]
    public void Should_RejectUnexpectedAndInvalidRecordFailures()
    {
        Assert.False(StorageFailureClassifier.IsTransient(new FormatException("corrupt backend record")));
        Assert.False(StorageFailureClassifier.IsTransient(new InvalidOperationException("provider state")));
        Assert.False(StorageFailureClassifier.IsTransient(new ObjectDisposedException("backend")));
    }

    [Fact]
    public void Should_RejectPermanentProviderFaultsHiddenByTransportWrappers()
    {
        // The outer IOException/HttpRequestException does not turn a corrupt
        // record, invalid provider state, or denied storage request into an outage.
        Exception[] errors =
        [
            new IOException("backend wrapper", new FormatException("corrupt marker")),
            new HttpRequestException("backend wrapper", new System.Text.Json.JsonException("malformed record")),
            new InvalidDataException("invalid binary record"),
            new IOException("backend wrapper", new InvalidOperationException("provider state invalid")),
            new IOException("backend wrapper",
                new HttpRequestException("backend denied request", null, HttpStatusCode.Forbidden)),
            new IOException("backend wrapper", new ProviderDatabaseException(false)),
            new IOException("backend wrapper", new ArgumentException("invalid storage key"))
        ];

        foreach (var error in errors)
        {
            Assert.False(StorageFailureClassifier.IsTransient(error));
        }
    }

    [Fact]
    public void Should_AllowRecognizedTransportFailuresThroughNestedWrappers()
    {
        Assert.True(StorageFailureClassifier.IsTransient(
            new HttpRequestException("connection reset",
                new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.ConnectionReset))));
        Assert.True(StorageFailureClassifier.IsTransient(
            new IOException("request failed", new TimeoutException("timed out"))));
        Assert.True(StorageFailureClassifier.IsTransient(
            new IOException("network failed", new IOException("network unavailable"))));
    }

    private sealed class ProviderDatabaseException(bool isTransient) : DbException("backend diagnostic")
    {
        public override bool IsTransient => isTransient;
    }
}
