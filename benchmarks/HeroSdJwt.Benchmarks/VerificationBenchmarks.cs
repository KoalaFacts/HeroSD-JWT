using System.Security.Cryptography;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(launchCount: 1, warmupCount: 3, iterationCount: 10)]
public class VerificationBenchmarks
{
    private byte[] _hmacKey = null!;
    private RSA _rsa = null!;
    private ECDsa _ecdsa = null!;
    private ECDsa _holderKey = null!;

    private SdJwt _sdJwtHmac = null!;
    private SdJwt _sdJwtRsa = null!;
    private SdJwtVerifier _verifier = null!;
    private SdJwtVerifier _verifierWithKeyBinding = null!;

    private string _presentation = null!;
    private string _presentationWithKeyBinding = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Generate keys
        _hmacKey = new byte[32];
        RandomNumberGenerator.Fill(_hmacKey);

        _rsa = RSA.Create(2048);
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Generate SD-JWTs
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example.com",
            ["sub"] = "user-123",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
            ["email"] = "alice@example.com",
            ["name"] = "Alice Smith",
            ["birthdate"] = "1990-01-01",
            ["address"] = new Dictionary<string, object>
            {
                ["street"] = "123 Main St",
                ["city"] = "Anytown",
                ["country"] = "US"
            }
        };

        var builder = new SdJwtBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm("SHA-256")
            .MakeClaimsSelective(new[] { "email", "name", "birthdate", "address.street", "address.city" });

        _sdJwtHmac = builder.SignWithHmac(_hmacKey);
        _sdJwtRsa = builder.SignWithRsa(_rsa);

        // Create presentations
        _presentation = _sdJwtHmac.ToPresentation(new[] { "email", "name" });

        // Create presentation with key binding
        var holderKeyJwk = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Convert.ToBase64String(_holderKey.ExportSubjectPublicKeyInfo()[27..59]),
            ["y"] = Convert.ToBase64String(_holderKey.ExportSubjectPublicKeyInfo()[59..91])
        });

        var builderWithKeyBinding = new SdJwtBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm("SHA-256")
            .WithHolderPublicKey(holderKeyJwk)
            .MakeClaimsSelective(new[] { "email", "name", "birthdate" });

        var sdJwtWithKeyBinding = builderWithKeyBinding.SignWithRsa(_rsa);
        _presentationWithKeyBinding = sdJwtWithKeyBinding.ToPresentation(
            new[] { "email", "name" },
            "https://verifier.example.com",
            "nonce-123",
            _holderKey
        );

        // Create verifiers
        _verifier = new SdJwtVerifier(new SdJwtVerificationOptions
        {
            KeyResolver = (kid) => Task.FromResult(_hmacKey),
            ExpectedIssuer = "https://issuer.example.com",
            ValidateExpirationTime = true
        });

        _verifierWithKeyBinding = new SdJwtVerifier(new SdJwtVerificationOptions
        {
            KeyResolver = (kid) => Task.FromResult(JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["kty"] = "RSA",
                ["n"] = Convert.ToBase64String(_rsa.ExportParameters(false).Modulus!),
                ["e"] = Convert.ToBase64String(_rsa.ExportParameters(false).Exponent!)
            })),
            ExpectedIssuer = "https://issuer.example.com",
            ExpectedAudience = "https://verifier.example.com",
            ExpectedNonce = "nonce-123",
            RequireKeyBinding = true,
            ValidateExpirationTime = true
        });
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _rsa.Dispose();
        _ecdsa.Dispose();
        _holderKey.Dispose();
    }

    [Benchmark]
    public async Task<VerificationResult> VerifyWithoutKeyBinding()
    {
        return await _verifier.VerifyPresentationAsync(_presentation);
    }

    [Benchmark]
    public async Task<VerificationResult> VerifyWithKeyBinding()
    {
        return await _verifierWithKeyBinding.VerifyPresentationAsync(_presentationWithKeyBinding);
    }

    [Benchmark]
    public bool TryVerifyWithoutKeyBinding()
    {
        return _verifier.TryVerifyPresentation(_presentation, out _);
    }
}
