using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Presentation;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Verification;
using HeroSdJwt.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.AspNetCore.Tests.Integration;

/// <summary>
/// End-to-end integration tests for SD-JWT authentication in ASP.NET Core.
/// Tests the complete flow from token issuance to verification.
/// </summary>
public class EndToEndAuthenticationTests : IDisposable
{
    private static long DefaultExp => DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
    private readonly byte[] _testKey;
    private readonly ISdJwtIssuer _issuer;
    private readonly ISdJwtPresenter _presenter;
    private bool _disposed;

    public EndToEndAuthenticationTests()
    {
        // Generate test key (HMAC)
        _testKey = new byte[32];
        RandomNumberGenerator.Fill(_testKey);

        // Create issuer and presenter for test setup
        var services = new ServiceCollection();
        services.AddSdJwtServices();
        var serviceProvider = services.BuildServiceProvider();

        _issuer = serviceProvider.GetRequiredService<ISdJwtIssuer>();
        _presenter = serviceProvider.GetRequiredService<ISdJwtPresenter>();
    }

    [Fact]
    public async Task AuthenticatedRequest_WithValidSdJwt_Succeeds()
    {
        // Arrange - Create test server with SD-JWT authentication
        using var host = await CreateTestHost();
        var client = host.GetTestClient();

        // Create SD-JWT
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["name"] = "John Doe",
            ["email"] = "john@example.com",
            ["role"] = "admin",
            ["exp"] = DefaultExp
        };

        // Mark name, email, and role as selectively disclosable
        var selectiveClaims = new[] { "name", "email", "role" };
        var sdJwt = _issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            _testKey,
            HeroSdJwt.Primitives.HashAlgorithm.Sha256,
            HeroSdJwt.Primitives.SignatureAlgorithm.HS256);
        var presentation = _presenter.FormatPresentation(
            _presenter.CreatePresentationWithAllClaims(sdJwt));

        // Act - Make authenticated request
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", presentation);

        var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var result = JsonSerializer.Deserialize<Dictionary<string, string>>(responseBody);

        Assert.NotNull(result);
        Assert.Equal("John Doe", result["name"]);
        Assert.Equal("john@example.com", result["email"]);
    }

    [Fact]
    public async Task UnauthenticatedRequest_Returns401()
    {
        // Arrange
        using var host = await CreateTestHost();
        var client = host.GetTestClient();

        // Act - Request without Authorization header
        var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AuthenticatedRequest_WithInvalidToken_Returns401()
    {
        // Arrange
        using var host = await CreateTestHost();
        var client = host.GetTestClient();

        // Act - Request with invalid token
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "invalid.token.here");

        var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AuthenticatedRequest_WithWrongKey_Returns401()
    {
        // Arrange
        using var host = await CreateTestHost();
        var client = host.GetTestClient();

        // Create SD-JWT with different key
        var wrongKey = new byte[32];
        RandomNumberGenerator.Fill(wrongKey);

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["name"] = "John Doe",
            ["exp"] = DefaultExp
        };

        var sdJwt = _issuer.CreateSdJwt(
            claims,
            Array.Empty<string>(),
            wrongKey,
            HeroSdJwt.Primitives.HashAlgorithm.Sha256,
            HeroSdJwt.Primitives.SignatureAlgorithm.HS256);
        var presentation = _presenter.FormatPresentation(
            _presenter.CreatePresentationWithAllClaims(sdJwt));

        // Act
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", presentation);

        var response = await client.GetAsync("/protected", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AuthenticatedRequest_DisclosedClaims_AreMappedToPrincipal()
    {
        // Arrange
        using var host = await CreateTestHost();
        var client = host.GetTestClient();

        // Create SD-JWT with selective disclosure
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["name"] = "Jane Smith",
            ["email"] = "jane@example.com",
            ["age"] = 30,
            ["ssn"] = "123-45-6789", // Sensitive - won't be disclosed
            ["exp"] = DefaultExp
        };

        var selectiveClaims = new[] { "email", "age", "ssn" };
        var sdJwt = _issuer.CreateSdJwt(
            claims,
            selectiveClaims,
            _testKey,
            HeroSdJwt.Primitives.HashAlgorithm.Sha256,
            HeroSdJwt.Primitives.SignatureAlgorithm.HS256);

        // Only disclose email and age, NOT ssn
        var presentation = _presenter.FormatPresentation(
            _presenter.CreatePresentation(sdJwt, new[] { "email", "age" }));

        // Act
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", presentation);

        var response = await client.GetAsync("/claims", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var result = JsonSerializer.Deserialize<Dictionary<string, string>>(responseBody);

        Assert.NotNull(result);
        Assert.Contains("email", result.Keys);
        Assert.Contains("age", result.Keys);
        Assert.DoesNotContain("ssn", result.Keys); // Should NOT be disclosed
        Assert.Equal("jane@example.com", result["email"]);
        Assert.Equal("30", result["age"]);
    }

    private async Task<IHost> CreateTestHost()
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSdJwtServices();
                    services.AddSingleton<ISdJwtVerifier>(_ =>
                        new SdJwtVerifier(
                            new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Symmetric },
                            new EcPublicKeyConverter(),
                            new SignatureValidator(),
                            new DigestValidator(),
                            new KeyBindingValidator(TimeProvider.System),
                            new ClaimValidator()));
                    services.AddAuthentication()
                        .AddSdJwt(options =>
                        {
                            options.VerificationOptions = new SdJwtVerificationOptions
                            {
                                ExpectedKeyType = VerificationKeyType.Symmetric
                            };
                            options.FallbackKey = _testKey;
                        });
                    services.AddAuthorization();
                });

                webHost.Configure(app =>
                {
                    // Correct middleware order for ASP.NET Core
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/protected", async context =>
                        {
                            if (!context.User.Identity?.IsAuthenticated ?? true)
                            {
                                context.Response.StatusCode = 401;
                                return;
                            }

                            var name = context.User.FindFirst("name")?.Value;
                            var email = context.User.FindFirst("email")?.Value;

                            var result = new Dictionary<string, string>
                            {
                                ["name"] = name ?? "",
                                ["email"] = email ?? ""
                            };

                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync(JsonSerializer.Serialize(result));
                        }).RequireAuthorization();

                        endpoints.MapGet("/claims", async context =>
                        {
                            if (!context.User.Identity?.IsAuthenticated ?? true)
                            {
                                context.Response.StatusCode = 401;
                                return;
                            }

                            var claims = context.User.Claims
                                .ToDictionary(c => c.Type, c => c.Value);

                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync(JsonSerializer.Serialize(claims));
                        }).RequireAuthorization();
                    });
                });
            });

        var host = await hostBuilder.StartAsync();
        return host;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
