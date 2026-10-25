using HeroSdJwt.Models;
using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.AspNetCore.Authentication;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;
using HeroSdJwt.Verification.Revocation;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.AspNetCore.Tests.Integration;

public sealed class AuthenticationPolicyTests : IDisposable
{
    private const string ISSUER = "https://issuer.example";
    private const string AUDIENCE = "https://api.example";
    private const string NONCE = "fresh-holder-challenge";
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Theory]
    [InlineData("https://other.example", AUDIENCE, false)]
    [InlineData(ISSUER, "https://other.example", false)]
    [InlineData(ISSUER, AUDIENCE, true)]
    public async Task PublicRegistration_RejectsPresentationOutsideSchemePolicy(string issuer, string audience, bool requireKeyBinding)
    {
        using var provider = BuildProvider(new SdJwtVerificationOptions
        {
            ExpectedIssuer = ISSUER,
            ExpectedAudiences = [AUDIENCE, "https://second-api.example"],
            RequireKeyBinding = requireKeyBinding,
            ExpectedNonce = requireKeyBinding ? NONCE : null
        });
        var result = await Authenticate(provider, CreateToken(issuer, audience));
        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
    }

    [Theory]
    [InlineData(AUDIENCE)]
    [InlineData("https://second-api.example")]
    public async Task PublicRegistration_AcceptsValidIssuerAndAudience(string audience)
    {
        using var provider = BuildProvider(new SdJwtVerificationOptions
        {
            ExpectedIssuer = ISSUER,
            ExpectedAudiences = [AUDIENCE, "https://second-api.example"]
        });
        Assert.True((await Authenticate(provider, CreateToken(ISSUER, audience))).Succeeded);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(120, true)]
    public async Task PublicRegistration_UsesSchemeClockSkew(int seconds, bool succeeds)
    {
        using var provider = BuildProvider(new SdJwtVerificationOptions { ClockSkew = TimeSpan.FromSeconds(seconds) });
        var token = CreateToken(ISSUER, AUDIENCE, DateTimeOffset.UtcNow.AddSeconds(-60).ToUnixTimeSeconds());
        Assert.Equal(succeeds, (await Authenticate(provider, token)).Succeeded);
    }

    [Theory]
    [InlineData(VerificationKeyType.Symmetric, true)]
    [InlineData(VerificationKeyType.Asymmetric, false)]
    public async Task PublicRegistration_UsesSchemeKeyType(VerificationKeyType keyType, bool succeeds)
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        using var provider = BuildProvider(new SdJwtVerificationOptions { ExpectedKeyType = keyType }, secret);
        var token = SdJwtIssuerBuilder.Create().WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(secret).Build().ToCombinedFormat();
        Assert.Equal(succeeds, (await Authenticate(provider, token)).Succeeded);
    }

    [Fact]
    public async Task PublicRegistration_MultipleSchemesRetainDistinctPolicies()
    {
        var services = BaseServices();
        var builder = services.AddAuthentication();
        builder.AddSdJwt("first", o => Configure(o, new SdJwtVerificationOptions { ExpectedIssuer = ISSUER }));
        builder.AddSdJwt("second", o => Configure(o, new SdJwtVerificationOptions { ExpectedIssuer = "https://other.example" }));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        var token = CreateToken(ISSUER, AUDIENCE);
        using var scope = provider.CreateScope();
        var context = NewContext(scope.ServiceProvider, token);
        Assert.True((await context.AuthenticateAsync("first")).Succeeded);
        Assert.False((await context.AuthenticateAsync("second")).Succeeded);
        using var nextScope = provider.CreateScope();
        var other = NewContext(nextScope.ServiceProvider, CreateToken("https://other.example", AUDIENCE));
        Assert.True((await other.AuthenticateAsync("second")).Succeeded);
        Assert.False((await other.AuthenticateAsync("first")).Succeeded);
    }

    [Theory]
    [InlineData(NONCE, AUDIENCE, true)]
    [InlineData("wrong-nonce", AUDIENCE, false)]
    [InlineData(NONCE, "https://other.example", false)]
    public async Task PublicRegistration_EnforcesHolderChallenge(string nonce, string audience, bool succeeds)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = SdJwtIssuerBuilder.Create().WithClaim("iss", ISSUER).WithClaim("aud", AUDIENCE)
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .WithKeyBinding(holder.ExportSubjectPublicKeyInfo()).SignWithEcdsa(_key.ExportPkcs8PrivateKey())
            .Build().ToCombinedFormat();
        var digest = Base64UrlEncoder.Encode(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));
        var binding = new KeyBindingGenerator().CreateKeyBindingJwt(holder.ExportECPrivateKey(), digest, audience, nonce);
        using var provider = BuildProvider(new SdJwtVerificationOptions
        {
            ExpectedAudience = AUDIENCE,
            ExpectedNonce = NONCE,
            RequireKeyBinding = true
        });
        Assert.Equal(succeeds, (await Authenticate(provider, token + binding)).Succeeded);
    }

    [Theory]
    [InlineData(HashAlgorithm.Sha256, true)]
    [InlineData(HashAlgorithm.Sha384, false)]
    public async Task PublicRegistration_EnforcesExpectedHashAlgorithm(HashAlgorithm expected, bool succeeds)
    {
        using var provider = BuildProvider(new SdJwtVerificationOptions { ExpectedHashAlgorithm = expected });
        Assert.Equal(succeeds, (await Authenticate(provider, CreateToken(ISSUER, AUDIENCE))).Succeeded);
    }

    [Fact]
    public async Task PublicRegistration_UsesRegisteredReplayValidator()
    {
        var services = BaseServices();
        var replay = new ReplayProtectionOptions { Enabled = true };
        services.AddSingleton(replay);
        services.AddSingleton<IJtiCache, InMemoryJtiCache>();
        services.AddScoped<JtiValidator>();
        services.AddAuthentication("test").AddSdJwt("test", o => Configure(o, new SdJwtVerificationOptions()));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        var token = CreateToken(ISSUER, AUDIENCE);
        Assert.True((await Authenticate(provider, token)).Succeeded);
        Assert.False((await Authenticate(provider, token)).Succeeded);
    }

    [Fact]
    public async Task PublicRegistration_UsesRegisteredRevocationStore()
    {
        var services = BaseServices();
        services.AddSingleton<IRevocationStore, InMemoryRevocationStore>();
        services.AddAuthentication("test").AddSdJwt("test", o => Configure(o, new SdJwtVerificationOptions()));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        var store = provider.GetRequiredService<IRevocationStore>();
        var token = CreateToken(ISSUER, AUDIENCE);
        Assert.True((await Authenticate(provider, token)).Succeeded);
        await store.RevokeJtiAsync("policy-test-id", DateTimeOffset.UtcNow.AddMinutes(10), TestContext.Current.CancellationToken);
        Assert.False((await Authenticate(provider, token)).Succeeded);
    }

    [Fact]
    public async Task PublicRegistration_PreservesScopedClaimValidator()
    {
        var services = BaseServices();
        services.AddScoped<IClaimValidator, ScopedClaimValidator>();
        services.AddAuthentication("test").AddSdJwt("test", o => Configure(o, new SdJwtVerificationOptions { ExpectedIssuer = ISSUER }));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var first = provider.CreateScope();
        using var second = provider.CreateScope();
        var firstValidator = (ScopedClaimValidator)first.ServiceProvider.GetRequiredService<IClaimValidator>();
        var secondValidator = (ScopedClaimValidator)second.ServiceProvider.GetRequiredService<IClaimValidator>();
        Assert.NotSame(firstValidator, secondValidator);
        Assert.True((await NewContext(first.ServiceProvider, CreateToken(ISSUER, AUDIENCE)).AuthenticateAsync("test")).Succeeded);
        Assert.Equal(1, firstValidator.IssuerChecks);
        Assert.Equal(0, secondValidator.IssuerChecks);
        Assert.True((await NewContext(second.ServiceProvider, CreateToken(ISSUER, AUDIENCE)).AuthenticateAsync("test")).Succeeded);
        Assert.Equal(1, secondValidator.IssuerChecks);
    }

    [Fact]
    public async Task CustomVerifierWithoutPolicyFactory_FailsClosedWithMigrationGuidance()
    {
        var services = BaseServices();
        services.AddScoped<ISdJwtVerifier, CustomVerifier>();
        services.AddAuthentication("test").AddSdJwt("test", o => Configure(o, new SdJwtVerificationOptions { ExpectedIssuer = ISSUER }));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        var result = await Authenticate(provider, CreateToken(ISSUER, AUDIENCE));
        Assert.False(result.Succeeded);
        Assert.Contains("ISdJwtVerifierFactory", result.Failure?.Message);
    }

    [Fact]
    public async Task DerivedVerifierWithoutFactoryOverride_FailsClosedWithMigrationGuidance()
    {
        var services = BaseServices();
        services.AddScoped<ISdJwtVerifier, UnmigratedDerivedVerifier>();
        services.AddAuthentication("test").AddSdJwt("test", o => Configure(o, new SdJwtVerificationOptions { ExpectedIssuer = ISSUER }));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        var result = await Authenticate(provider, CreateToken(ISSUER, AUDIENCE));
        Assert.False(result.Succeeded);
        Assert.Contains("Derived verifiers must override", result.Failure?.Message);
        Assert.Contains("ISdJwtVerifierFactory.CreateVerifier", result.Failure?.Message);
    }

    [Theory]
    [InlineData(ISSUER, AUDIENCE, true)]
    [InlineData("https://other.example", AUDIENCE, false)]
    [InlineData(ISSUER, "https://customization-rejects.example", false)]
    public async Task DerivedVerifierWithFactoryOverride_EnforcesSchemeAndRetainsCustomization(string issuer, string audience, bool succeeds)
    {
        var services = BaseServices();
        services.AddScoped<AudienceRestrictedClaimValidator>();
        services.AddScoped<ISdJwtVerifier>(sp => new MigratedDerivedVerifier(
            new SdJwtVerificationOptions(), sp.GetRequiredService<AudienceRestrictedClaimValidator>()));
        services.AddAuthentication("test").AddSdJwt("test", o => Configure(o, new SdJwtVerificationOptions { ExpectedIssuer = ISSUER }));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();
        var sourceVerifier = (MigratedDerivedVerifier)scope.ServiceProvider.GetRequiredService<ISdJwtVerifier>();
        var customValidator = scope.ServiceProvider.GetRequiredService<AudienceRestrictedClaimValidator>();
        var result = await NewContext(scope.ServiceProvider, CreateToken(issuer, audience)).AuthenticateAsync("test");
        Assert.Equal(succeeds, result.Succeeded);
        Assert.Equal(1, sourceVerifier.FactoryCalls);
        Assert.Equal(1, customValidator.AudienceChecks);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CustomPolicyFactory_PreservesScopedVerifierAndEnforcesSchemePolicy(bool useResolver)
    {
        var services = BaseServices();
        services.AddScoped<ISdJwtVerifier>(_ => new PolicyAwareVerifier(new SdJwtVerifier(
            new SdJwtVerificationOptions(), new EcPublicKeyConverter(), new SignatureValidator(),
            new DigestValidator(), new KeyBindingValidator(), new ClaimValidator())));
        services.AddAuthentication("test").AddSdJwt("test", o =>
        {
            Configure(o, new SdJwtVerificationOptions { ExpectedIssuer = ISSUER });
            if (useResolver)
            {
                o.KeyResolver = _ => _key.ExportSubjectPublicKeyInfo();
            }
        });
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var first = provider.CreateScope();
        using var second = provider.CreateScope();
        var firstVerifier = (PolicyAwareVerifier)first.ServiceProvider.GetRequiredService<ISdJwtVerifier>();
        var secondVerifier = (PolicyAwareVerifier)second.ServiceProvider.GetRequiredService<ISdJwtVerifier>();
        Assert.NotSame(firstVerifier, secondVerifier);
        Assert.True((await NewContext(first.ServiceProvider, CreateToken(ISSUER, AUDIENCE)).AuthenticateAsync("test")).Succeeded);
        Assert.False((await NewContext(second.ServiceProvider, CreateToken("https://other.example", AUDIENCE)).AuthenticateAsync("test")).Succeeded);
        Assert.Equal(ISSUER, firstVerifier.LastPolicy?.ExpectedIssuer);
        Assert.Equal(ISSUER, secondVerifier.LastPolicy?.ExpectedIssuer);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PublicRegistration_ForwardsCancellationAndRejectsCanceledRequest(bool canceled)
    {
        var services = BaseServices();
        var cache = new CancellationObservingCache();
        services.AddSingleton<IJtiCache>(cache);
        services.AddSingleton(new ReplayProtectionOptions { Enabled = true });
        services.AddScoped<JtiValidator>();
        services.AddAuthentication("test").AddSdJwt("test", o => Configure(o, new SdJwtVerificationOptions()));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();
        using var cancellation = new CancellationTokenSource();
        if (canceled)
        {
            cancellation.Cancel();
        }
        var context = NewContext(scope.ServiceProvider, CreateToken(ISSUER, AUDIENCE));
        context.RequestAborted = cancellation.Token;
        var result = await context.AuthenticateAsync("test");
        Assert.Equal(!canceled, result.Succeeded);
        Assert.Equal(canceled ? CancellationToken.None : cancellation.Token, cache.ObservedToken);
    }

    private sealed class UnmigratedDerivedVerifier() : SdJwtVerifier(
        new SdJwtVerificationOptions(), new EcPublicKeyConverter(), new SignatureValidator(),
        new DigestValidator(), new KeyBindingValidator(), new ClaimValidator());

    private sealed class MigratedDerivedVerifier(SdJwtVerificationOptions options, AudienceRestrictedClaimValidator customValidator)
        : SdJwtVerifier(options, new EcPublicKeyConverter(), new SignatureValidator(),
            new DigestValidator(), new KeyBindingValidator(), customValidator)
    {
        public int FactoryCalls { get; private set; }

        public override ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions policy)
        {
            FactoryCalls++;
            return new MigratedDerivedVerifier(policy, customValidator);
        }
    }

    private sealed class AudienceRestrictedClaimValidator : IClaimValidator
    {
        private readonly ClaimValidator _inner = new();
        public int AudienceChecks { get; private set; }

        public bool ValidateAudience(JsonElement payload, IReadOnlyCollection<string>? expectedAudiences)
        {
            AudienceChecks++;
            return _inner.ValidateAudience(payload, expectedAudiences) && _inner.ValidateAudience(payload, [AUDIENCE]);
        }

        public bool ValidateIssuer(JsonElement payload, string? expectedIssuer) => _inner.ValidateIssuer(payload, expectedIssuer);
        public bool ValidateTemporalClaims(JsonElement payload, SdJwtVerificationOptions options, DateTimeOffset? currentTime = null) =>
            _inner.ValidateTemporalClaims(payload, options, currentTime);
    }

    private sealed class CancellationObservingCache : IJtiCache
    {
        public CancellationToken ObservedToken { get; private set; }
        public Task<bool> TryAddAsync(string issuer, string jti, TimeSpan ttl, CancellationToken cancellationToken = default)
        {
            ObservedToken = cancellationToken;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(true);
        }

        public Task<bool> ExistsAsync(string issuer, string jti, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task RemoveAsync(string issuer, string jti, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private class SyncOnlyVerifier(ISdJwtVerifier inner) : ISdJwtVerifier
    {
        public VerificationResult VerifyPresentation(string presentation, byte[] publicKey, HashAlgorithm? expectedHashAlgorithm = null) =>
            inner.VerifyPresentation(presentation, publicKey, expectedHashAlgorithm);
        public VerificationResult TryVerifyPresentation(string presentation, byte[] publicKey, HashAlgorithm? expectedHashAlgorithm = null) =>
            inner.TryVerifyPresentation(presentation, publicKey, expectedHashAlgorithm);
        public VerificationResult VerifyPresentation(string presentation, KeyResolver? keyResolver, byte[]? fallbackKey = null, HashAlgorithm? expectedHashAlgorithm = null) =>
            inner.VerifyPresentation(presentation, keyResolver, fallbackKey, expectedHashAlgorithm);
        public VerificationResult TryVerifyPresentation(string presentation, KeyResolver? keyResolver, byte[]? fallbackKey = null, HashAlgorithm? expectedHashAlgorithm = null) =>
            inner.TryVerifyPresentation(presentation, keyResolver, fallbackKey, expectedHashAlgorithm);
    }

    private sealed class PolicyAwareVerifier(SdJwtVerifier template) : SyncOnlyVerifier(template), ISdJwtVerifierFactory
    {
        public SdJwtVerificationOptions? LastPolicy { get; private set; }
        public ISdJwtVerifier CreateVerifier(SdJwtVerificationOptions options)
        {
            LastPolicy = options;
            return new SyncOnlyVerifier(template.CreateVerifier(options));
        }
    }

    private sealed class ScopedClaimValidator : IClaimValidator
    {
        private readonly ClaimValidator _inner = new();
        public int IssuerChecks { get; private set; }

        public bool ValidateIssuer(JsonElement payload, string? expectedIssuer)
        {
            IssuerChecks++;
            return _inner.ValidateIssuer(payload, expectedIssuer);
        }

        public bool ValidateTemporalClaims(JsonElement payload, SdJwtVerificationOptions options, DateTimeOffset? currentTime = null) =>
            _inner.ValidateTemporalClaims(payload, options, currentTime);

        public bool ValidateAudience(JsonElement payload, IReadOnlyCollection<string>? expectedAudiences) =>
            _inner.ValidateAudience(payload, expectedAudiences);
    }

    private sealed class CustomVerifier : ISdJwtVerifier
    {
        public VerificationResult VerifyPresentation(string presentation, byte[] publicKey, HashAlgorithm? expectedHashAlgorithm = null) =>
            throw new InvalidOperationException("Unconfigured custom verifier must not be called");
        public VerificationResult TryVerifyPresentation(string presentation, byte[] publicKey, HashAlgorithm? expectedHashAlgorithm = null) =>
            VerifyPresentation(presentation, publicKey, expectedHashAlgorithm);
        public VerificationResult VerifyPresentation(string presentation, KeyResolver? keyResolver, byte[]? fallbackKey = null, HashAlgorithm? expectedHashAlgorithm = null) =>
            throw new InvalidOperationException("Unconfigured custom verifier must not be called");
        public VerificationResult TryVerifyPresentation(string presentation, KeyResolver? keyResolver, byte[]? fallbackKey = null, HashAlgorithm? expectedHashAlgorithm = null) =>
            VerifyPresentation(presentation, keyResolver, fallbackKey, expectedHashAlgorithm);
    }

    private ServiceProvider BuildProvider(SdJwtVerificationOptions policy, byte[]? key = null)
    {
        var services = BaseServices();
        services.AddAuthentication("test").AddSdJwt("test", o => Configure(o, policy, key));
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    private static ServiceCollection BaseServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        return services;
    }

    private void Configure(SdJwtAuthenticationOptions options, SdJwtVerificationOptions policy, byte[]? key = null)
    {
        options.FallbackKey = key ?? _key.ExportSubjectPublicKeyInfo();
        options.VerificationOptions = policy;
    }

    private string CreateToken(string issuer, string audience, long? expiration = null) =>
        SdJwtIssuerBuilder.Create().WithClaim("iss", issuer).WithClaim("aud", audience).WithClaim("jti", "policy-test-id")
            .WithClaim("exp", expiration ?? DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithEcdsa(_key.ExportPkcs8PrivateKey()).Build().ToCombinedFormat();

    private static async Task<AuthenticateResult> Authenticate(ServiceProvider provider, string token)
    {
        using var scope = provider.CreateScope();
        return await NewContext(scope.ServiceProvider, token).AuthenticateAsync("test");
    }

    private static DefaultHttpContext NewContext(IServiceProvider services, string token)
    {
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Headers.Authorization = "Bearer " + token;
        return context;
    }

    public void Dispose() => _key.Dispose();
}
