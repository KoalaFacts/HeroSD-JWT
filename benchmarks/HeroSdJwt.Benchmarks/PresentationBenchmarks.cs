using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;

namespace HeroSdJwt.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(launchCount: 1, warmupCount: 3, iterationCount: 10)]
public class PresentationBenchmarks
{
    private byte[] _hmacKey = null!;
    private SdJwt _sdJwt = null!;
    private ECDsa _holderKey = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Generate keys
        _hmacKey = new byte[32];
        RandomNumberGenerator.Fill(_hmacKey);
        _holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Generate SD-JWT with many selectable claims
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example.com",
            ["sub"] = "user-123",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        };

        for (int i = 0; i < 50; i++)
        {
            claims[$"claim_{i}"] = $"value_{i}";
        }

        var builder = new SdJwtBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm("SHA-256")
            .MakeClaimsSelective(claims.Keys.Where(k => k.StartsWith("claim_")));

        _sdJwt = builder.SignWithHmac(_hmacKey);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _holderKey.Dispose();
    }

    [Benchmark]
    public string CreatePresentationFewClaims()
    {
        // Disclose only 5 claims
        return _sdJwt.ToPresentation(new[] { "claim_0", "claim_1", "claim_2", "claim_3", "claim_4" });
    }

    [Benchmark]
    public string CreatePresentationManyClaims()
    {
        // Disclose 25 claims
        var claimsToDisclose = Enumerable.Range(0, 25).Select(i => $"claim_{i}").ToArray();
        return _sdJwt.ToPresentation(claimsToDisclose);
    }

    [Benchmark]
    public string CreatePresentationAllClaims()
    {
        // Disclose all 50 claims
        return _sdJwt.ToPresentationWithAllClaims();
    }

    [Benchmark]
    public string CreatePresentationWithKeyBinding()
    {
        // Disclose 5 claims with key binding
        return _sdJwt.ToPresentation(
            new[] { "claim_0", "claim_1", "claim_2", "claim_3", "claim_4" },
            audience: "https://verifier.example.com",
            nonce: "nonce-123",
            holderKey: _holderKey
        );
    }
}
