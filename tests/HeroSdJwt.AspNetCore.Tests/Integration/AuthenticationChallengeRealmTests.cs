using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace HeroSdJwt.AspNetCore.Tests.Integration;

public sealed class AuthenticationChallengeRealmTests
{
    [Theory]
    [InlineData("api.example.com:8443", "Bearer realm=\"api.example.com:8443\"")]
    [InlineData("api.example.com\" injected=\"true", "Bearer realm=\"api.example.com\\\" injected=\\\"true\"")]
    [InlineData("api.example.com\\other", "Bearer realm=\"api.example.com\\\\other\"")]
    [InlineData("api.example.com\r\nX-Injected: yes", "Bearer")]
    public async Task Should_NotAllowUntrustedHostToChangeChallengeParameters(string host, string expected)
    {
        var services = new ServiceCollection();
        services.AddLogging();
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
        // Keep the malformed Host value raw; HostString's setter normalises IDNs.
        context.Request.Headers.Host = host;

        await context.ChallengeAsync("SdJwt");

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(expected, context.Response.Headers.WWWAuthenticate.ToString());
    }
}
