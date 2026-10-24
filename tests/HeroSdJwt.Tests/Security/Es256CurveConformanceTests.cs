using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 7518 ES256 requires NIST P-256, not any elliptic curve with a 256-bit key.
/// The secp256k1 vectors are signed independently of the library and validated
/// with an external ECDSA SHA-256 implementation. Their header declares ES256.
/// </summary>
public sealed class Es256CurveConformanceTests
{
    private const string ISSUER = "https://issuer.example.test";
    private const string AUDIENCE = "https://verifier.example.test";
    private const string NONCE = "secp256k1-regression";
    private const string SD_HASH = "test-sd-hash";

    // Test-only secp256k1 SubjectPublicKeyInfo and SEC1 private key fixtures.
    private static readonly byte[] Secp256k1PublicKey = Convert.FromBase64String(
        "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE5RZiQ2oLjAVSXWR3SUY8X0AUmw5sOQHCcoBGMnvsxN1/EBookky59vQxeYH5HXlsUsUh0owjt821PiWpoteMrg==");
    private static readonly byte[] Secp256k1PrivateKey = Convert.FromBase64String(
        "MHQCAQEEIAAAAAAAiMVkPhKqfdZpX0sFODGr6ZIZNylAE5MBkCgjoAcGBSuBBAAKoUQDQgAE5RZiQ2oLjAVSXWR3SUY8X0AUmw5sOQHCcoBGMnvsxN1/EBookky59vQxeYH5HXlsUsUh0owjt821PiWpoteMrg==");

    // Genuine ECDSA/SHA-256 signature with JOSE raw R||S bytes over this
    // compact KB-JWT, using the secp256k1 private key above (not NIST P-256).
    private const string Secp256k1SignedProof =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9." +
        "eyJzZF9oYXNoIjoidGVzdC1zZC1oYXNoIiwiYXVkIjoiaHR0cHM6Ly92ZXJpZmllci5leGFtcGxlLnRlc3QiLCJub25jZSI6InNlY3AyNTZrMS1yZWdyZXNzaW9uIiwiaWF0IjoxODkzNDU2MDAwfQ." +
        "IuAYlNCJYk30Fjvg-tuIJcJ-t0-HciG_vggoDdHFx00gyhIk6PT7-i8bf7Wv8uFgeDG_CgSmCDeg4Dwq2LjgXA";

    [Fact]
    public void Should_RejectGenuinelySignedSecp256k1Proof_ButAcceptNistP256()
    {
        var clock = new FixedTimeProvider(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var validator = new KeyBindingValidator(clock);

        using var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p256Proof = new KeyBindingGenerator(clock).CreateKeyBindingJwt(
            p256.ExportECPrivateKey(), SD_HASH, AUDIENCE, NONCE);

        Assert.True(validator.ValidateKeyBinding(
            p256Proof, p256.ExportSubjectPublicKeyInfo(), SD_HASH, AUDIENCE, NONCE));
        Assert.False(validator.ValidateKeyBinding(
            Secp256k1SignedProof, Secp256k1PublicKey, SD_HASH, AUDIENCE, NONCE));
    }

    [Fact]
    public void Should_RejectSecp256k1_WhenGeneratingProofOrConvertingJwk()
    {
        var clock = new FixedTimeProvider(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.Throws<ArgumentException>(() => new KeyBindingGenerator(clock).CreateKeyBindingJwt(
            Secp256k1PrivateKey, SD_HASH, AUDIENCE, NONCE));
        Assert.Throws<ArgumentException>(() => new EcPublicKeyConverter().ToJwk(Secp256k1PublicKey));

        using var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Equal("P-256", new EcPublicKeyConverter().ToJwk(p256.ExportSubjectPublicKeyInfo())["crv"]);
    }

    [Fact]
    public void Should_RejectUnsupportedLegacyHolderCurve_BeforeCallingKeyBindingValidator()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var cnf = new Dictionary<string, object> { ["jwk"] = Convert.ToBase64String(Secp256k1PublicKey) };
        var issued = SdJwtIssuerBuilder.Create()
            .WithClaim("iss", ISSUER)
            .WithClaim("aud", AUDIENCE)
            .WithClaim("cnf", cnf)
            .SignWithHmac(secret)
            .Build()
            .ToCombinedFormat();

        var bindingValidator = new PermissiveKeyBindingValidator();
        var verifier = new SdJwtVerifier(
            new SdJwtVerificationOptions
            {
                ExpectedIssuer = ISSUER,
                ExpectedAudience = AUDIENCE,
                ExpectedNonce = NONCE,
                ExpectedKeyType = VerificationKeyType.Symmetric,
                RequireKeyBinding = true
            },
            new EcPublicKeyConverter(), new SignatureValidator(), new DigestValidator(),
            bindingValidator, new ClaimValidator());

        // The permissive test collaborator isolates the verifier's curve guard.
        // An unsupported holder key must be rejected before it is called.
        var result = verifier.TryVerifyPresentation(issued + Secp256k1SignedProof, secret);

        Assert.False(result.IsValid);
        Assert.False(bindingValidator.WasCalled);
    }

    private sealed class FixedTimeProvider(DateTimeOffset time) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => time;
    }

    private sealed class PermissiveKeyBindingValidator : IKeyBindingValidator
    {
        public bool WasCalled { get; private set; }

        public bool ValidateKeyBinding(string keyBindingJwt, byte[] holderPublicKey,
            string expectedSdJwtHash, IReadOnlyCollection<string> expectedAudiences,
            string? expectedNonce = null)
        {
            WasCalled = true;
            return true;
        }
    }
}
