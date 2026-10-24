using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;

namespace HeroSdJwt.AspNetCore.Tests.Integration;

public class SchemePolicyRegressionTests
{
    [Theory]
    [InlineData("issuer", false)]
    [InlineData("audience", false)]
    [InlineData("binding", false)]
    [InlineData("valid", true)]
    public async Task Should_ApplyNamedSchemePolicyWithoutChangingOtherSchemes(string policy, bool accepted)
    {
        using var rsa = RSA.Create(2048);
        var key = rsa.ExportSubjectPublicKeyInfo();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication().AddSdJwt("strict", options =>
        {
            options.FallbackKey = key;
            options.VerificationOptions = new SdJwtVerificationOptions
            {
                ExpectedIssuer = policy == "issuer" ? "other-issuer" : "issuer",
                ExpectedAudience = policy == "audience" ? "other-api" : "api",
                ExpectedNonce = "nonce",
                RequireKeyBinding = policy == "binding"
            };
        }).AddSdJwt("relaxed", options => options.FallbackKey = key);
        await using var provider = services.BuildServiceProvider();
        var jwt = new JwtSigner().CreateJwt(new Dictionary<string, object>
        {
            ["iss"] = "issuer",
            ["aud"] = "api",
            ["sub"] = "subject",
            ["exp"] = 4102444800L
        }, rsa.ExportPkcs8PrivateKey(), SignatureAlgorithm.RS256) + "~";
        foreach (var scheme in new[] { "strict", "relaxed", "strict" })
        {
            await using var scope = provider.CreateAsyncScope();
            var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            context.Request.Headers.Authorization = "Bearer " + jwt;
            var result = await context.AuthenticateAsync(scheme);
            Assert.Equal(scheme == "relaxed" || accepted, result.Succeeded);
        }
    }
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task Should_PreserveExplicitVerifierPolicy(bool requireKeyBinding, bool unusedDefaultDependencyFails)
    {
        using var rsa = RSA.Create(2048);
        var services = new ServiceCollection();
        services.AddLogging();
        var verifier = new SdJwtVerifier(new SdJwtVerificationOptions
        {
            ExpectedIssuer = "custom-issuer",
            ExpectedAudience = "api",
            ExpectedNonce = "nonce",
            RequireKeyBinding = requireKeyBinding
        }, new EcPublicKeyConverter(), new SignatureValidator(), new DigestValidator(),
            new KeyBindingValidator(), new ClaimValidator());
        services.AddSingleton<ISdJwtVerifier>(verifier);
        if (unusedDefaultDependencyFails)
        {
            services.AddSingleton<ISignatureValidator>(_ => throw new InvalidOperationException("Unused default dependency must not be resolved"));
        }
        services.AddAuthentication().AddSdJwt(options => options.FallbackKey = rsa.ExportSubjectPublicKeyInfo());
        await using var provider = services.BuildServiceProvider();
        foreach (var issuer in new[] { "wrong-issuer", "custom-issuer" })
        {
            var jwt = new JwtSigner().CreateJwt(new Dictionary<string, object>
            {
                ["iss"] = issuer,
                ["aud"] = "api",
                ["exp"] = 4102444800L
            }, rsa.ExportPkcs8PrivateKey(), SignatureAlgorithm.RS256) + "~";
            await using var scope = provider.CreateAsyncScope();
            var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            context.Request.Headers.Authorization = "Bearer " + jwt;
            var result = await context.AuthenticateAsync("SdJwt");
            Assert.Equal(issuer == "custom-issuer" && !requireKeyBinding, result.Succeeded);
        }
    }
}
