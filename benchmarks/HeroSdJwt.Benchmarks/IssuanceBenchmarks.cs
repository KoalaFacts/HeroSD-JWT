using BenchmarkDotNet.Attributes;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;
using SdJwtHashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(launchCount: 1, warmupCount: 3, iterationCount: 10)]
public class IssuanceBenchmarks
{
    private byte[] hmacKey = null!;
    private RSA rsa = null!;
    private ECDsa ecdsa = null!;

    private Dictionary<string, object> claims10 = null!;
    private Dictionary<string, object> claims50 = null!;
    private Dictionary<string, object> claims100 = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Generate keys
        hmacKey = new byte[32];
        RandomNumberGenerator.Fill(hmacKey);

        rsa = RSA.Create(2048);
        ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Generate claim sets
        claims10 = GenerateClaims(10);
        claims50 = GenerateClaims(50);
        claims100 = GenerateClaims(100);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        rsa.Dispose();
        ecdsa.Dispose();
    }

    private static Dictionary<string, object> GenerateClaims(int count)
    {
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example.com",
            ["sub"] = "user-" + Guid.NewGuid(),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        };

        for (int i = 0; i < count - 4; i++)
        {
            claims[$"claim_{i}"] = $"value_{i}";
        }

        return claims;
    }

    // ====== HS256 (HMAC-SHA256) Benchmarks ======

    [Benchmark]
    [ArgumentsSource(nameof(ClaimCounts))]
    public SdJwt IssueWithHmac(int claimCount)
    {
        var claims = claimCount switch
        {
            10 => claims10,
            50 => claims50,
            100 => claims100,
            _ => throw new ArgumentException(nameof(claimCount))
        };

        var builder = new SdJwtBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm(SdJwtHashAlgorithm.Sha256)
            .MakeSelective(claims.Keys.Where(k => !Constants.ReservedClaims.Contains(k)).ToArray());

        return builder.SignWithHmac(hmacKey).Build();
    }

    // ====== RS256 (RSA-SHA256) Benchmarks ======

    [Benchmark]
    [ArgumentsSource(nameof(ClaimCounts))]
    public SdJwt IssueWithRsa(int claimCount)
    {
        var claims = claimCount switch
        {
            10 => claims10,
            50 => claims50,
            100 => claims100,
            _ => throw new ArgumentException(nameof(claimCount))
        };

        var builder = new SdJwtBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm(SdJwtHashAlgorithm.Sha256)
            .MakeSelective(claims.Keys.Where(k => !Constants.ReservedClaims.Contains(k)).ToArray());

        var rsaPrivateKey = rsa.ExportPkcs8PrivateKey();
        return builder.SignWithRsa(rsaPrivateKey).Build();
    }

    // ====== ES256 (ECDSA-P256-SHA256) Benchmarks ======

    [Benchmark]
    [ArgumentsSource(nameof(ClaimCounts))]
    public SdJwt IssueWithEcdsa(int claimCount)
    {
        var claims = claimCount switch
        {
            10 => claims10,
            50 => claims50,
            100 => claims100,
            _ => throw new ArgumentException(nameof(claimCount))
        };

        var builder = new SdJwtBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm(SdJwtHashAlgorithm.Sha256)
            .MakeSelective(claims.Keys.Where(k => !Constants.ReservedClaims.Contains(k)).ToArray());

        var ecdsaPrivateKey = ecdsa.ExportPkcs8PrivateKey();
        return builder.SignWithEcdsa(ecdsaPrivateKey).Build();
    }

    public IEnumerable<int> ClaimCounts()
    {
        yield return 10;
        yield return 50;
        yield return 100;
    }
}
