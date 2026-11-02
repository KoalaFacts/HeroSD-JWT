using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

public class DisclosureParserSizeAdmissionTests
{
    [Fact]
    public void Should_RejectOversizedDisclosureBeforeBase64Decoding()
    {
        var parser = new DisclosureParser();
        var oversizedMalformed = new string('!', Constants.MAX_JWT_SIZE_BYTES + 1);

        Assert.Throws<MalformedDisclosureException>(() => parser.Parse(oversizedMalformed));
    }

    [Fact]
    public void Should_RejectOversizedValidDisclosureBeforeJsonParsing()
    {
        var parser = new DisclosureParser();
        var json = $"[\\\"salt\\\",\\\"claim\\\",\\\"{new string('a', Constants.MAX_JWT_SIZE_BYTES)}\\\"]";
        var encoded = Base64UrlEncoder.Encode(json);
        Assert.True(encoded.Length > Constants.MAX_JWT_SIZE_BYTES);

        Assert.Throws<MalformedDisclosureException>(() => parser.Parse(encoded));
        Assert.Throws<MalformedDisclosureException>(() => parser.GetClaimName(encoded));
    }

    [Fact]
    public void Should_AcceptLargeDisclosureWithinCombinedFormatLimit()
    {
        const int payloadLength = 40_000;
        var json = $"[\\\"salt\\\",\\\"claim\\\",\\\"{new string('a', payloadLength)}\\\"]";
        var encoded = Base64UrlEncoder.Encode(json);
        Assert.True(encoded.Length < Constants.MAX_JWT_SIZE_BYTES);

        var disclosure = new DisclosureParser().Parse(encoded);

        Assert.Equal(payloadLength, disclosure.ClaimValue.GetString()!.Length);
    }
}
