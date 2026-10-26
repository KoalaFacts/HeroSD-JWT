using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A forged holder proof must not reach verifier clock services, and a separator
/// flood must not allocate proportionally to the number of JWT components.
/// </summary>
public class KeyBindingSignatureAdmissionTests
{
    private const string AUDIENCE = "https://verifier.example.test";
    private const string NONCE = "holder-challenge";
    private const string SD_HASH = "credential-digest";

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Should_NotReadClockForInvalidHolderSignature(bool wrongKey, bool multipleAudiences)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var anotherHolder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), SD_HASH, AUDIENCE, NONCE);

        var parts = proof.Split('.');
        Assert.Equal(3, parts.Length);
        var signature = Base64UrlEncoder.DecodeBytes(parts[2]);
        if (!wrongKey)
        {
            signature[0] ^= 0x01;
            proof = parts[0] + "." + parts[1] + "." + Base64UrlEncoder.Encode(signature);
        }

        var verificationKey = wrongKey
            ? anotherHolder.ExportSubjectPublicKeyInfo()
            : holder.ExportSubjectPublicKeyInfo();
        var signingInput = System.Text.Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
        using var actualKey = ECDsa.Create();
        actualKey.ImportSubjectPublicKeyInfo(verificationKey, out _);
        Assert.False(actualKey.VerifyData(signingInput, signature, HashAlgorithmName.SHA256));

        // Before the fix, timestamp inspection invoked GetUtcNow on an
        // unauthenticated holder payload, leaking this exception to callers.
        var validator = new KeyBindingValidator(new RejectingTimeProvider());
        var accepted = multipleAudiences
            ? validator.ValidateKeyBinding(proof, verificationKey, SD_HASH, [AUDIENCE], NONCE)
            : validator.ValidateKeyBinding(proof, verificationKey, SD_HASH, AUDIENCE, NONCE);

        Assert.False(accepted);
    }

    [Fact]
    public void Should_StillReadClockForGenuinelySignedHolderProof()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), SD_HASH, AUDIENCE, NONCE);
        var timeProvider = new CountingTimeProvider();

        Assert.True(new KeyBindingValidator(timeProvider).ValidateKeyBinding(
            proof, holder.ExportSubjectPublicKeyInfo(), SD_HASH, AUDIENCE, NONCE));
        Assert.Equal(1, timeProvider.CallCount);
    }

    [Fact]
    public void Should_BoundAllocationsForMalformedJwtSeparatorFlood()
    {
        // The 64-KiB size gate alone does not prevent Split('.') from
        // allocating tens of thousands of array slots for a hostile input.
        var verifier = new KeyBindingValidator();
        var key = Array.Empty<byte>();
        Assert.False(verifier.ValidateKeyBinding("a.b.c.d", key, SD_HASH, AUDIENCE, NONCE));

        var proof = new string('.', Constants.MAX_JWT_SIZE_BYTES);
        var before = GC.GetAllocatedBytesForCurrentThread();
        var accepted = verifier.ValidateKeyBinding(proof, key, SD_HASH, AUDIENCE, NONCE);
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.False(accepted);
        Assert.InRange(allocatedBytes, 0, 256_000);
    }

    private sealed class RejectingTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() =>
            throw new InvalidOperationException("Unsigned holder claims consulted the clock.");
    }

    private sealed class CountingTimeProvider : TimeProvider
    {
        public int CallCount { get; private set; }

        public override DateTimeOffset GetUtcNow()
        {
            CallCount++;
            return DateTimeOffset.UtcNow;
        }
    }
}
