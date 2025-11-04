using HeroSdJwt.Internal.Ed25519;
using System;
using Xunit;
using Xunit.Abstractions;

namespace HeroSdJwt.Tests.Unit.Cryptography;

/// <summary>
/// Debug tests to verify Ed25519 base point and key generation
/// </summary>
public class Ed25519DebugTests
{
    private readonly ITestOutputHelper _output;

    public Ed25519DebugTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Debug_BasePoint_Encoding()
    {
        // Get our base point
        var basePoint = LookupTables.GetBasePoint();

        // Encode it to bytes
        byte[] encoded = new byte[32];
        GroupOperations.ge_p3_tobytes(encoded, 0, ref basePoint);

        _output.WriteLine("Base point encoded bytes:");
        _output.WriteLine(BitConverter.ToString(encoded).Replace("-", ""));

        // RFC 8032 expects: 5866666666666666666666666666666666666666666666666666666666666666
        var expectedBytes = HexToBytes("5866666666666666666666666666666666666666666666666666666666666666");
        _output.WriteLine("\nExpected bytes:");
        _output.WriteLine(BitConverter.ToString(expectedBytes).Replace("-", ""));

        Assert.Equal(expectedBytes, encoded);
    }

    [Fact]
    public void Debug_KeyGeneration_TestVector1()
    {
        // Test vector 1 seed
        var seed = HexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

        // Generate key
        var (publicKey, _) = Ed25519.KeyPairFromSeed(seed);

        _output.WriteLine("Generated public key:");
        _output.WriteLine(BitConverter.ToString(publicKey).Replace("-", ""));

        var expectedPublicKey = HexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        _output.WriteLine("\nExpected public key:");
        _output.WriteLine(BitConverter.ToString(expectedPublicKey).Replace("-", ""));

        Assert.Equal(expectedPublicKey, publicKey);
    }

    private static byte[] HexToBytes(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }
}
