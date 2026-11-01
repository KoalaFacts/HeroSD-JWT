using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// ES256 signs the exact ASCII header.payload bytes, including the dot.
/// Verify both the bounded stack path and the larger managed-buffer path.
/// </summary>
public class KeyBindingSigningInputTests
{
    private const string SD_HASH = "sd-jwt-digest";
    private const string NONCE = "challenge-☕";

    [Theory]
    [InlineData(12, false)]
    [InlineData(900, true)]
    public void Should_ValidateSignedProofAcrossSigningInputBufferBoundary(
        int audienceSuffixLength, bool usesLargeBuffer)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = holder.ExportSubjectPublicKeyInfo();
        var audience = "https://verifier.example/" + new string('x', audienceSuffixLength);
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), SD_HASH, audience, NONCE);

        var signingInputLength = proof.LastIndexOf('.');
        Assert.Equal(usesLargeBuffer, signingInputLength > 1024);

        var validator = new KeyBindingValidator();
        Assert.True(validator.ValidateKeyBinding(proof, key, SD_HASH, audience, NONCE));

        // An unchanged-length signature forgery must still fail on both paths.
        var segments = proof.Split('.');
        var signature = Base64UrlEncoder.DecodeBytes(segments[2]);
        signature[0] ^= 1;
        var forged = segments[0] + "." + segments[1] + "." + Base64UrlEncoder.Encode(signature);
        Assert.False(validator.ValidateKeyBinding(forged, key, SD_HASH, audience, NONCE));
    }

    [Theory]
    [InlineData(63)]
    [InlineData(65)]
    public void Should_RejectNonEs256SignatureLengths_BeforeConsultingClock(int length)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = holder.ExportSubjectPublicKeyInfo();
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), SD_HASH, "https://verifier.example", NONCE);

        var lastDot = proof.LastIndexOf('.');
        var malformed = proof[..(lastDot + 1)] + Base64UrlEncoder.Encode(new byte[length]);

        Assert.False(new KeyBindingValidator(new RejectingClock()).ValidateKeyBinding(
            malformed, key, SD_HASH, "https://verifier.example", NONCE));
    }

    private sealed class RejectingClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() =>
            throw new InvalidOperationException("Unauthenticated KB-JWT consulted the clock.");
    }
}
