using HeroSdJwt.Verification;
using System.Data.Common;
using System.Net;
using System.Net.Http;

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
    public void Should_RejectUnexpectedAndInvalidRecordFailures()
    {
        Assert.False(StorageFailureClassifier.IsTransient(new FormatException("corrupt backend record")));
        Assert.False(StorageFailureClassifier.IsTransient(new InvalidOperationException("provider state")));
        Assert.False(StorageFailureClassifier.IsTransient(new ObjectDisposedException("backend")));
    }

    private sealed class ProviderDatabaseException(bool isTransient) : DbException("backend diagnostic")
    {
        public override bool IsTransient => isTransient;
    }
}
