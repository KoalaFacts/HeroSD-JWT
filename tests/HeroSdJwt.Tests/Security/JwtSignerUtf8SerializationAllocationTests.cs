using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using System.Buffers;
using System.Reflection;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// JWT signing should encode the UTF-8 JSON bytes already produced by
/// Utf8JsonWriter, without round-tripping through a UTF-16 JSON string.
/// </summary>
public sealed class JwtSignerUtf8SerializationAllocationTests
{
    [Fact]
    public void Should_PreserveJwtWireBytesAndAvoidRedundantUtf8RoundTrip()
    {
        var method = typeof(JwtSigner).GetMethod(
            "SerializeDictionaryBase64Url", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("Missing UTF-8 JWT serializer.");
        var serialize = method.CreateDelegate<Func<Dictionary<string, object>, string>>();

        var unicodeClaim = new Dictionary<string, object>
        {
            ["data"] = "Unicode: \uD83E\uDD98, quote: \" and slash: \\"
        };
        Assert.Equal(LegacyEncodeSingleClaim(unicodeClaim), serialize(unicodeClaim));

        var claims = new Dictionary<string, object>
        {
            ["data"] = new string('x', 16_384)
        };

        var expectedPayload = LegacyEncodeSingleClaim(claims);
        Assert.Equal(expectedPayload, serialize(claims));

        var jwt = new JwtSigner().CreateJwt(claims, new byte[32], SignatureAlgorithm.HS256);
        Assert.Equal(expectedPayload, jwt.Split('.')[1]);

        // Both paths write identical JSON to an ArrayBufferWriter. The legacy
        // path then allocates a UTF-16 string and another UTF-8 array solely
        // to recover the bytes it just wrote. Measure after JIT warm-up.
        for (var i = 0; i < 32; i++)
        {
            _ = LegacyEncodeSingleClaim(claims);
            _ = serialize(claims);
        }

        const int Iterations = 64;
        var legacyBytes = MeasureAllocations(() => LegacyEncodeSingleClaim(claims), Iterations);
        var directBytes = MeasureAllocations(() => serialize(claims), Iterations);

        // A 16-KiB ASCII claim guarantees >16 KiB of redundant UTF-8
        // conversion buffers in the legacy path. Allow runtime variance
        // while ensuring this regression is not silently reintroduced.
        Assert.True(
            legacyBytes - directBytes >= 8_192L * Iterations,
            $"Legacy JSON encoding allocated {legacyBytes / Iterations} bytes/call, " +
            $"direct UTF-8 encoding allocated {directBytes / Iterations} bytes/call.");
    }

    private static string LegacyEncodeSingleClaim(Dictionary<string, object> claims)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { MaxDepth = 64 }))
        {
            writer.WriteStartObject();
            writer.WriteString("data", (string)claims["data"]);
            writer.WriteEndObject();
            writer.Flush();
        }

        return Base64UrlEncoder.Encode(System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    private static long MeasureAllocations(Func<string> action, int iterations)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < iterations; i++)
        {
            GC.KeepAlive(action());
        }

        return GC.GetAllocatedBytesForCurrentThread() - before;
    }
}
