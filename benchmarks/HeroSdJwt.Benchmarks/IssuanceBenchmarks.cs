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
    private byte[] _hmacKey = null!;
    private RSA _rsa = null!;
    private ECDsa _ecdsa = null!;

    private Dictionary<string, object> _claims10 = null!;
    private Dictionary<string, object> _claims50 = null!;
    private Dictionary<string, object> _claims100 = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Generate keys
        _hmacKey = new byte[32];
        RandomNumberGenerator.Fill(_hmacKey);

        _rsa = RSA.Create(2048);
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Generate claim sets
        _claims10 = GenerateClaims(10);
        _claims50 = GenerateClaims(50);
        _claims100 = GenerateClaims(100);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _rsa.Dispose();
        _ecdsa.Dispose();
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
            10 => _claims10,
            50 => _claims50,
            100 => _claims100,
            _ => throw new ArgumentException(nameof(claimCount))
        };

        var builder = new SdJwtIssuerBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm(SdJwtHashAlgorithm.Sha256)
            .MakeSelective(claims.Keys.Where(k => !Constants.ReservedClaims.Contains(k)).ToArray());

        return builder.SignWithHmac(_hmacKey).Build();
    }

    // ====== RS256 (RSA-SHA256) Benchmarks ======

    [Benchmark]
    [ArgumentsSource(nameof(ClaimCounts))]
    public SdJwt IssueWithRsa(int claimCount)
    {
        var claims = claimCount switch
        {
            10 => _claims10,
            50 => _claims50,
            100 => _claims100,
            _ => throw new ArgumentException(nameof(claimCount))
        };

        var builder = new SdJwtIssuerBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm(SdJwtHashAlgorithm.Sha256)
            .MakeSelective(claims.Keys.Where(k => !Constants.ReservedClaims.Contains(k)).ToArray());

        var rsaPrivateKey = _rsa.ExportPkcs8PrivateKey();
        return builder.SignWithRsa(rsaPrivateKey).Build();
    }

    // ====== ES256 (ECDSA-P256-SHA256) Benchmarks ======

    [Benchmark]
    [ArgumentsSource(nameof(ClaimCounts))]
    public SdJwt IssueWithEcdsa(int claimCount)
    {
        var claims = claimCount switch
        {
            10 => _claims10,
            50 => _claims50,
            100 => _claims100,
            _ => throw new ArgumentException(nameof(claimCount))
        };

        var builder = new SdJwtIssuerBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm(SdJwtHashAlgorithm.Sha256)
            .MakeSelective(claims.Keys.Where(k => !Constants.ReservedClaims.Contains(k)).ToArray());

        var ecdsaPrivateKey = _ecdsa.ExportPkcs8PrivateKey();
        return builder.SignWithEcdsa(ecdsaPrivateKey).Build();
    }

    public IEnumerable<int> ClaimCounts()
    {
        yield return 10;
        yield return 50;
        yield return 100;
    }
}
