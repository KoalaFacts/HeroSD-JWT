using HeroSdJwt.Internal.Ed25519;

namespace HeroSdJwt.Tests.Security;

public class Ed25519CanonicalPointDecodingTests
{
    [Theory]
    [InlineData(0xED, 0x7F)]
    [InlineData(0xEE, 0x7F)]
    [InlineData(0xED, 0xFF)]
    public void Should_RejectOutOfRangeY_When_DecodingCompressedPoint(int firstByte, int lastByte)
    {
        // RFC 8032 §5.1.3 rejects y >= p (2^255 - 19), irrespective
        // of the sign bit. Reduction modulo p must not admit aliases.
        var encoded = new byte[32];
        Array.Fill(encoded, (byte)0xFF);
        encoded[0] = (byte)firstByte;
        encoded[31] = (byte)lastByte;

        Assert.False(GroupOperations.GeFromBytesNegateVartime(out _, encoded, 0));
    }

    [Fact]
    public void Should_RejectNegativeZero_When_DecodingCompressedPoint()
    {
        // y=1 has x=0, for which the sign bit must be zero.
        var encoded = new byte[32];
        encoded[0] = 1;
        encoded[31] = 0x80;

        Assert.False(GroupOperations.GeFromBytesNegateVartime(out _, encoded, 0));
    }

    [Fact]
    public void Should_KeepAcceptingCanonicalBasePoint()
    {
        // RFC 8032 base point encoding.
        var encoded = new byte[32];
        encoded[0] = 0x58;
        Array.Fill(encoded, (byte)0x66, 1, 31);

        Assert.True(GroupOperations.GeFromBytesNegateVartime(out _, encoded, 0));
    }
}
