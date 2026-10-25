using System.Security.Cryptography;
using System.Text.Json;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Uses independently encoded and signed JWTs so issuer/presenter helpers cannot
/// mask mistakes in verification or in the key-binding digest algorithm.
/// </summary>
public class VerificationAdmissionSecurityTests
{
    private const string ISSUER = "https://issuer.example.test";
    private const string AUDIENCE = "https://verifier.example.test";
    private const string NONCE = "verifier-challenge";
    private const string JTI = "same-public-jti";

    [Theory]
    [InlineData("issuer-signature", ErrorCode.InvalidSignature)]
    [InlineData("issuer-signature-blank-disclosure", ErrorCode.InvalidSignature)]
    [InlineData("issuer", ErrorCode.InvalidInput)]
    [InlineData("audience", ErrorCode.InvalidInput)]
    [InlineData("not-before", ErrorCode.TokenExpired)]
    [InlineData("digest", ErrorCode.DigestMismatch)]
    [InlineData("holder-signature", ErrorCode.InvalidSignature)]
    [InlineData("holder-nonce", ErrorCode.InvalidSignature)]
    [InlineData("holder-algorithm", ErrorCode.InvalidSignature)]
    [InlineData("reconstruction", ErrorCode.MalformedDisclosure)]
    public async Task RejectedPresentation_DoesNotReserveReplayIdentifier(string failure, ErrorCode expectedError)
    {
        using var fixture = new SignedFixture();
        var replayOptions = new ReplayProtectionOptions { Enabled = true };
        using var cache = new InMemoryJtiCache(replayOptions);
        var verifier = CreateVerifier(cache, replayOptions, failure == "issuer" ? "https://other-issuer.example.test" : ISSUER);
        var validPresentation = fixture.CreatePresentation();
        var rejected = fixture.CreatePresentation(failure: failure);

        var invalidResult = await verifier.TryVerifyPresentationAsync(rejected, fixture.IssuerKey, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(invalidResult.IsValid);
        Assert.Contains(expectedError, invalidResult.Errors);
        Assert.False(await cache.ExistsAsync(ISSUER, JTI, TestContext.Current.CancellationToken), $"The rejected {failure} presentation reserved the replay identifier.");

        // Restore the expected issuer policy after its negative case; both tokens
        // have the exact same issuer/jti cache key.
        var validVerifier = CreateVerifier(cache, replayOptions);
        var accepted = await validVerifier.TryVerifyPresentationAsync(validPresentation, fixture.IssuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(accepted.IsValid, accepted.ErrorDetails);
        Assert.Equal("alice@example.test", accepted.DisclosedClaims["email"].GetString());
        Assert.True(await cache.ExistsAsync(ISSUER, JTI, TestContext.Current.CancellationToken));

        var replay = await validVerifier.TryVerifyPresentationAsync(validPresentation, fixture.IssuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(replay.IsValid);
        Assert.Contains(ErrorCode.ReplayAttack, replay.Errors);
    }

    [Theory]
    [InlineData("sha-256")]
    [InlineData("sha-384")]
    [InlineData("sha-512")]
    [InlineData(null)]
    public async Task IndependentHolderProof_UsesCredentialHashAlgorithm(string? algorithm)
    {
        using var fixture = new SignedFixture();
        var replayOptions = new ReplayProtectionOptions { Enabled = true };
        using var cache = new InMemoryJtiCache(replayOptions);
        var verifier = CreateVerifier(cache, replayOptions);

        var result = await verifier.TryVerifyPresentationAsync(fixture.CreatePresentation(algorithm), fixture.IssuerKey, cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.Equal("alice@example.test", result.DisclosedClaims["email"].GetString());
    }

    [Theory]
    [InlineData("sha-256")]
    [InlineData(null)]
    public async Task OptionsHashAlgorithmPolicy_IsAppliedWhenCallDoesNotOverride(string? algorithm)
    {
        using var fixture = new SignedFixture();
        var replayOptions = new ReplayProtectionOptions { Enabled = true };
        using var cache = new InMemoryJtiCache(replayOptions);
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedIssuer(ISSUER)
            .WithExpectedAudience(AUDIENCE)
            .WithExpectedNonce(NONCE)
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithExpectedHashAlgorithm(HashAlgorithm.Sha384)
            .WithReplayProtection(new JtiValidator(cache, replayOptions))
            .Build();

        var invalid = await verifier.TryVerifyPresentationAsync(fixture.CreatePresentation(algorithm),
            fixture.IssuerKey, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(invalid.IsValid);
        Assert.Contains(ErrorCode.HashAlgorithmMismatch, invalid.Errors);
        Assert.False(await cache.ExistsAsync(ISSUER, JTI, TestContext.Current.CancellationToken));
        var valid = await verifier.TryVerifyPresentationAsync(fixture.CreatePresentation("sha-384"),
            fixture.IssuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(valid.IsValid, valid.ErrorDetails);
    }

    [Theory]
    [InlineData("sha-256")]
    [InlineData("sha-384")]
    public async Task ExplicitHashAlgorithmArgument_CannotOverrideConfiguredPolicy(string algorithm)
    {
        using var fixture = new SignedFixture();
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedAudience(AUDIENCE)
            .WithExpectedNonce(NONCE)
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithExpectedHashAlgorithm(HashAlgorithm.Sha384)
            .Build();

        var result = await verifier.TryVerifyPresentationAsync(fixture.CreatePresentation(algorithm),
            fixture.IssuerKey, HashAlgorithm.Sha256, TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.HashAlgorithmMismatch, result.Errors);
    }

    [Theory]
    [InlineData("sha-384")]
    [InlineData("sha-512")]
    public async Task HolderProofUsingSha256ForStrongerCredentialAlgorithm_IsRejectedWithoutReplayAdmission(string algorithm)
    {
        using var fixture = new SignedFixture();
        var replayOptions = new ReplayProtectionOptions { Enabled = true };
        using var cache = new InMemoryJtiCache(replayOptions);
        var verifier = CreateVerifier(cache, replayOptions);

        var invalid = await verifier.TryVerifyPresentationAsync(
            fixture.CreatePresentation(algorithm, hashOverride: "sha-256"), fixture.IssuerKey, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(invalid.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, invalid.Errors);
        Assert.False(await cache.ExistsAsync(ISSUER, JTI, TestContext.Current.CancellationToken));
        var valid = await verifier.TryVerifyPresentationAsync(fixture.CreatePresentation(algorithm), fixture.IssuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(valid.IsValid, valid.ErrorDetails);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("ES384")]
    [InlineData("es256")]
    [InlineData(256)]
    [InlineData("")]
    [MemberData(nameof(InvalidAlgorithmHeaderValues))]
    public void HolderProof_WithValidEs256SignatureAndInvalidAlgorithmHeader_IsRejected(object? algorithm)
    {
        using var fixture = new SignedFixture();
        var validator = new KeyBindingValidator();
        var proof = fixture.CreateHolderProof("independent-sd-hash", algorithm);

        // The signature really verifies against this very header and payload;
        // rejection must be due to the algorithm policy, not broken crypto.
        var parts = proof.Split('.');
        Assert.True(fixture.HolderKey.VerifyData(System.Text.Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}"),
            Decode(parts[2]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.False(validator.ValidateKeyBinding(proof, fixture.HolderKey.ExportSubjectPublicKeyInfo(),
            "independent-sd-hash", AUDIENCE, NONCE));
    }

    public static IEnumerable<object[]> InvalidAlgorithmHeaderValues =>
    [
        [JsonSerializer.Deserialize<JsonElement>("null")],
        [JsonSerializer.Deserialize<JsonElement>("{}")],
        [JsonSerializer.Deserialize<JsonElement>("[]")]
    ];

    [Fact]
    public async Task CancellationDuringReadOnlyValidation_DoesNotReserveReplayIdentifier()
    {
        using var fixture = new SignedFixture();
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var replayOptions = new ReplayProtectionOptions { Enabled = true };
        using var cache = new InMemoryJtiCache(replayOptions);
        var verifier = CreateVerifier(cache, replayOptions, keyBindingValidator: new CancelAfterValidation(cancellation));
        var presentation = fixture.CreatePresentation();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            verifier.VerifyPresentationAsync(presentation, fixture.IssuerKey, cancellationToken: cancellation.Token));

        Assert.False(await cache.ExistsAsync(ISSUER, JTI, TestContext.Current.CancellationToken));
        var accepted = await CreateVerifier(cache, replayOptions).TryVerifyPresentationAsync(
            presentation, fixture.IssuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(accepted.IsValid, accepted.ErrorDetails);
    }

    [Fact]
    public void HolderProof_WithEs256Header_StillRequiresValidSignature()
    {
        using var fixture = new SignedFixture();
        var validator = new KeyBindingValidator();
        var validProof = fixture.CreateHolderProof("independent-sd-hash", "ES256");
        var invalidProof = fixture.CreateHolderProof("independent-sd-hash", "ES256", invalidSignature: true);

        Assert.True(validator.ValidateKeyBinding(validProof, fixture.HolderKey.ExportSubjectPublicKeyInfo(),
            "independent-sd-hash", AUDIENCE, NONCE));
        Assert.False(validator.ValidateKeyBinding(invalidProof, fixture.HolderKey.ExportSubjectPublicKeyInfo(),
            "independent-sd-hash", AUDIENCE, NONCE));
    }

    private static SdJwtVerifier CreateVerifier(IJtiCache cache, ReplayProtectionOptions replayOptions,
        string expectedIssuer = ISSUER, IKeyBindingValidator? keyBindingValidator = null) =>
        SdJwtVerifierBuilder.Create()
            .WithExpectedIssuer(expectedIssuer)
            .WithExpectedAudience(AUDIENCE)
            .WithExpectedNonce(NONCE)
            .WithKeyBindingValidator(keyBindingValidator ?? new KeyBindingValidator())
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithClockSkew(TimeSpan.Zero)
            .RequireKeyBinding()
            .WithReplayProtection(new JtiValidator(cache, replayOptions))
            .Build();

    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string EncodeJson(object value) => Encode(JsonSerializer.SerializeToUtf8Bytes(value));
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));

    private sealed class CancelAfterValidation(CancellationTokenSource cancellation) : IKeyBindingValidator
    {
        public bool ValidateKeyBinding(string keyBindingJwt, byte[] holderPublicKey, string expectedSdJwtHash,
            IReadOnlyCollection<string> expectedAudiences, string? expectedNonce = null)
        {
            var valid = new KeyBindingValidator().ValidateKeyBinding(keyBindingJwt, holderPublicKey,
                expectedSdJwtHash, expectedAudiences, expectedNonce);
            cancellation.Cancel();
            return valid;
        }
    }

    private sealed class SignedFixture : IDisposable
    {
        public byte[] IssuerKey { get; } = RandomNumberGenerator.GetBytes(32);
        public ECDsa HolderKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public string CreatePresentation(string? algorithm = "sha-256", string? failure = null, string? hashOverride = null)
        {
            var disclosure = failure == "reconstruction"
                ? EncodeJson(new[] { "salt" })
                : EncodeJson(new[] { "independent-disclosure-salt", "email", "alice@example.test" });
            var holderParameters = HolderKey.ExportParameters(false);
            var payload = new Dictionary<string, object>
            {
                ["iss"] = ISSUER,
                ["aud"] = failure == "audience" ? "https://wrong-audience.example.test" : AUDIENCE,
                ["jti"] = JTI,
                ["exp"] = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),
                ["nbf"] = DateTimeOffset.UtcNow.AddMinutes(failure == "not-before" ? 5 : -1).ToUnixTimeSeconds(),
                ["_sd"] = new[] { Hash(disclosure, algorithm) },
                ["cnf"] = new { jwk = new { kty = "EC", crv = "P-256", x = Encode(holderParameters.Q.X!), y = Encode(holderParameters.Q.Y!) } }
            };
            if (algorithm != null)
            {
                payload["_sd_alg"] = algorithm;
            }

            var issuerSigningInput = $"{EncodeJson(new { alg = "HS256", typ = "sd+jwt" })}.{EncodeJson(payload)}";
            var issuerSigningKey = failure is "issuer-signature" or "issuer-signature-blank-disclosure"
                ? RandomNumberGenerator.GetBytes(32) : IssuerKey;
            var jwt = $"{issuerSigningInput}.{Encode(HMACSHA256.HashData(issuerSigningKey, System.Text.Encoding.UTF8.GetBytes(issuerSigningInput)))}";
            if (failure == "digest")
            {
                disclosure = EncodeJson(new[] { "different-salt", "email", "mallory@example.test" });
            }
            else if (failure == "issuer-signature-blank-disclosure")
            {
                disclosure = " ";
            }

            var sdJwt = $"{jwt}~{disclosure}~";
            var kb = CreateHolderProof(Hash(sdJwt, hashOverride ?? algorithm),
                failure == "holder-algorithm" ? "none" : "ES256",
                failure == "holder-signature", failure == "holder-nonce" ? "wrong-nonce" : NONCE);
            return sdJwt + kb;
        }

        public string CreateHolderProof(string sdHash, object? algorithm, bool invalidSignature = false, string nonce = NONCE)
        {
            var header = new Dictionary<string, object> { ["typ"] = "kb+jwt" };
            if (algorithm != null)
            {
                header["alg"] = algorithm;
            }
            var payload = new { sd_hash = sdHash, aud = AUDIENCE, nonce, iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds() };
            var signingInput = $"{EncodeJson(header)}.{EncodeJson(payload)}";
            var signature = HolderKey.SignData(System.Text.Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (invalidSignature)
            {
                signature[0] ^= 1;
            }
            return $"{signingInput}.{Encode(signature)}";
        }

        // These expectations are generated entirely with BCL primitives, without
        // the production DigestCalculator, issuer, presenter or KB generator.
        private static string Hash(string value, string? algorithm) => Encode(algorithm switch
        {
            "sha-384" => SHA384.HashData(System.Text.Encoding.UTF8.GetBytes(value)),
            "sha-512" => SHA512.HashData(System.Text.Encoding.UTF8.GetBytes(value)),
            _ => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))
        });

        public void Dispose() => HolderKey.Dispose();
    }
}
