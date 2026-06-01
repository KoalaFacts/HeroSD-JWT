using HeroSdJwt.AspNetCore.Authentication;
using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Presentation;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Verification;
using HeroSdJwt.Primitives;
using Microsoft.AspNetCore.Authentication;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.AspNetCore.Tests.Integration;

/// <summary>
/// Branch-focused tests for <see cref="SdJwtAuthenticationHandler"/>.
/// The existing end-to-end tests cover the happy path and a couple of failures; these target the
/// handler's less-travelled branches: token extraction edge cases, the challenge (WWW-Authenticate)
/// response, SaveToken, the KeyResolver code path, and array-claim mapping.
/// </summary>
public class AuthenticationHandlerBranchTests : IDisposable
{
    private static long DefaultExp => DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
    private readonly byte[] _testKey;
    private readonly ISdJwtIssuer _issuer;
    private readonly ISdJwtPresenter _presenter;
    private bool _disposed;

    public AuthenticationHandlerBranchTests()
    {
        _testKey = new byte[32];
        RandomNumberGenerator.Fill(_testKey);

        var services = new ServiceCollection();
        _ = services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();
        _issuer = serviceProvider.GetRequiredService<ISdJwtIssuer>();
        _presenter = serviceProvider.GetRequiredService<ISdJwtPresenter>();
    }

    private string CreatePresentation(Dictionary<string, object> claims, string[] selective, string[] disclose)
    {
        var sdJwt = _issuer.CreateSdJwt(
            claims, selective, _testKey, HashAlgorithm.Sha256, SignatureAlgorithm.HS256);
        return _presenter.FormatPresentation(_presenter.CreatePresentation(sdJwt, disclose));
    }

    [Fact]
    public async Task NonBearerAuthorizationScheme_IsIgnored_Returns401()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();

        // "Basic" scheme should be ignored by the SD-JWT handler -> NoResult -> challenge.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", "dXNlcjpwYXNz");

        var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task EmptyBearerToken_IsIgnored_Returns401()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();

        client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer    ");

        var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Challenge_Sets_WwwAuthenticate_Header()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();

        var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains("WWW-Authenticate"));
        var header = string.Join(",", response.Headers.GetValues("WWW-Authenticate"));
        Assert.Contains("Bearer", header);
        Assert.Contains("realm=", header);
    }

    [Fact]
    public async Task CustomTokenScheme_AcceptsMatchingScheme()
    {
        using var host = await CreateTestHost(configure: o => o.TokenScheme = "DPoP");
        var client = host.GetTestClient();

        var presentation = CreatePresentation(
            new Dictionary<string, object> { ["sub"] = "u1", ["name"] = "Sam", ["exp"] = DefaultExp },
            ["name"], ["name"]);

        client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", $"DPoP {presentation}");

        var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CustomTokenScheme_RejectsBearerScheme()
    {
        using var host = await CreateTestHost(configure: o => o.TokenScheme = "DPoP");
        var client = host.GetTestClient();

        var presentation = CreatePresentation(
            new Dictionary<string, object> { ["sub"] = "u1", ["name"] = "Sam", ["exp"] = DefaultExp },
            ["name"], ["name"]);

        // Sent with Bearer, but handler expects DPoP -> ignored -> 401
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", presentation);

        var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task SaveToken_StoresAccessToken()
    {
        using var host = await CreateTestHost(configure: o => o.SaveToken = true);
        var client = host.GetTestClient();

        var presentation = CreatePresentation(
            new Dictionary<string, object> { ["sub"] = "u1", ["name"] = "Sam", ["exp"] = DefaultExp },
            ["name"], ["name"]);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", presentation);

        var response = await client.GetAsync("/token", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(presentation, body);
    }

    [Fact]
    public async Task KeyResolverConfigured_TakesResolverBranch_AndSucceeds()
    {
        // When a KeyResolver is configured, the handler uses the resolver-based verification overload.
        using var host = await CreateTestHost(configure: o =>
        {
            o.KeyResolver = _ => _testKey;
            o.FallbackKey = _testKey;
        });
        var client = host.GetTestClient();

        var presentation = CreatePresentation(
            new Dictionary<string, object> { ["sub"] = "u1", ["name"] = "Sam", ["exp"] = DefaultExp },
            ["name"], ["name"]);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", presentation);

        var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ArrayDisclosedClaim_MapsToMultipleClaims()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "u1",
            ["roles"] = new[] { "admin", "auditor" },
            ["exp"] = DefaultExp
        };
        var presentation = CreatePresentation(claims, ["roles"], ["roles"]);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", presentation);

        var response = await client.GetAsync("/rolelist", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var roles = JsonSerializer.Deserialize<List<string>>(body)!;
        Assert.Contains("admin", roles);
        Assert.Contains("auditor", roles);
    }

    private async Task<IHost> CreateTestHost(Action<SdJwtAuthenticationOptions>? configure = null)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                _ = webHost.UseTestServer();
                _ = webHost.ConfigureServices(services =>
                {
                    _ = services.AddRouting();
                    _ = services.AddSdJwtServices();
                    _ = services.AddSingleton<ISdJwtVerifier>(_ =>
                        new SdJwtVerifier(
                            new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Symmetric },
                            new EcPublicKeyConverter(),
                            new SignatureValidator(),
                            new DigestValidator(),
                            new KeyBindingValidator(TimeProvider.System),
                            new ClaimValidator()));
                    _ = services.AddAuthentication()
                        .AddSdJwt(options =>
                        {
                            options.VerificationOptions = new SdJwtVerificationOptions
                            {
                                ExpectedKeyType = VerificationKeyType.Symmetric
                            };
                            options.FallbackKey = _testKey;
                            configure?.Invoke(options);
                        });
                    _ = services.AddAuthorization();
                });

                _ = webHost.Configure(app =>
                {
                    _ = app.UseRouting();
                    _ = app.UseAuthentication();
                    _ = app.UseAuthorization();
                    _ = app.UseEndpoints(endpoints =>
                    {
                        _ = endpoints.MapGet("/protected", async context =>
                        {
                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync(JsonSerializer.Serialize(new { ok = true }));
                        }).RequireAuthorization();

                        _ = endpoints.MapGet("/token", async context =>
                        {
                            var token = await context.GetTokenAsync("access_token");
                            await context.Response.WriteAsync(token ?? "");
                        }).RequireAuthorization();

                        _ = endpoints.MapGet("/rolelist", async context =>
                        {
                            var roles = context.User.FindAll("roles").Select(c => c.Value).ToList();
                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync(JsonSerializer.Serialize(roles));
                        }).RequireAuthorization();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
