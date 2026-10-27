using HeroSdJwt.Cryptography;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;
using Xunit;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Contract;

public class VerificationEntryPointTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_VerifySignedDisclosuresThroughBothInterfaces_When_UsingNewEntryPoints(bool useResolver)
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var presentation = CreatePresentation(key, useResolver);
        var verifier = CreateVerifier();
        ISdJwtVerifier sync = verifier;
        ISdJwtVerifierAsync asyncVerifier = verifier;
        byte[]? Resolve(string _)
        {
            return key;
        }

        var syncResult = useResolver ? sync.Verify(presentation, Resolve) : sync.Verify(presentation, key);
        var syncTryResult = useResolver ? sync.TryVerify(presentation, Resolve) : sync.TryVerify(presentation, key);
        var asyncResult = useResolver
            ? await asyncVerifier.VerifyAsync(presentation, Resolve)
            : await asyncVerifier.VerifyAsync(presentation, key);
        var asyncTryResult = useResolver
            ? await asyncVerifier.TryVerifyAsync(presentation, Resolve)
            : await asyncVerifier.TryVerifyAsync(presentation, key);

        VerificationResult[] results = [syncResult, syncTryResult, asyncResult, asyncTryResult];
        foreach (var result in results)
        {
            Assert.True(result.IsValid);
            Assert.Equal("alice@example.test", result.DisclosedClaims["email"].GetString());
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_SeparateThrowingAndResultContracts_When_SignatureIsInvalid(bool useResolver)
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var wrongKey = KeyGenerator.Instance.GenerateHmacKey();
        var presentation = CreatePresentation(key, useResolver);
        var verifier = CreateVerifier();
        byte[]? Resolve(string _)
        {
            return wrongKey;
        }

        VerificationResult VerifySync()
        {
            return useResolver ? verifier.Verify(presentation, Resolve) : verifier.Verify(presentation, wrongKey);
        }
        Task<VerificationResult> VerifyAsync()
        {
            return useResolver ? verifier.VerifyAsync(presentation, Resolve) : verifier.VerifyAsync(presentation, wrongKey);
        }

        var syncError = Assert.Throws<SdJwtException>(VerifySync);
        var asyncError = await Assert.ThrowsAsync<SdJwtException>(VerifyAsync);
        var syncResult = useResolver ? verifier.TryVerify(presentation, Resolve) : verifier.TryVerify(presentation, wrongKey);
        var asyncResult = useResolver
            ? await verifier.TryVerifyAsync(presentation, Resolve)
            : await verifier.TryVerifyAsync(presentation, wrongKey);

        Assert.False(syncResult.IsValid);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, syncResult.Errors);
        Assert.Equal(syncError.ErrorCode, asyncError.ErrorCode);
        Assert.Contains(asyncError.ErrorCode, asyncResult.Errors);
    }

    [Fact]
    public async Task Should_KeepHashPolicyAndFallbackSemantics_When_UsingNewEntryPoints()
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var verifier = CreateVerifier();
        var presentation = CreatePresentation(key, false);
        Assert.True((await verifier.VerifyAsync(presentation, (KeyResolver?)null, fallbackKey: key)).IsValid);
        Assert.False((await verifier.TryVerifyAsync(presentation, key, HashAlgorithm.Sha384)).IsValid);
        Assert.False(verifier.TryVerify(presentation, key, HashAlgorithm.Sha384).IsValid);

        byte[]? UnknownKey(string _)
        {
            return null;
        }
        var unknown = await verifier.TryVerifyAsync(CreatePresentation(key, true), UnknownKey, fallbackKey: key);
        Assert.False(unknown.IsValid);
        Assert.Contains(ErrorCode.KeyIdNotFound, unknown.Errors);
        var missing = await verifier.TryVerifyAsync(presentation, (KeyResolver?)null);
        Assert.Contains(ErrorCode.KeyResolverMissing, missing.Errors);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_PropagateResolverCancellation_When_UsingTryOrThrowingEntryPoint(bool tryApi)
    {
        var key = KeyGenerator.Instance.GenerateHmacKey();
        var presentation = CreatePresentation(key, true);
        var verifier = CreateVerifier();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var expected = new OperationCanceledException(cancellation.Token);
        byte[]? Resolve(string _)
        {
            throw expected;
        }
        Task<VerificationResult> InvokeAsync()
        {
            return tryApi ? verifier.TryVerifyAsync(presentation, Resolve) : verifier.VerifyAsync(presentation, Resolve);
        }
        VerificationResult InvokeSync()
        {
            return tryApi ? verifier.TryVerify(presentation, Resolve) : verifier.Verify(presentation, Resolve);
        }

        Assert.Same(expected, await Assert.ThrowsAnyAsync<OperationCanceledException>(InvokeAsync));
        Assert.Same(expected, Assert.ThrowsAny<OperationCanceledException>(InvokeSync));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Should_NotInvokeVerifier_When_RequestIsAlreadyCanceled(bool useResolver, bool tryApi)
    {
        var verifier = new RecordingVerifier();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Task<VerificationResult> Invoke()
        {
            return InvokeAsync(verifier, useResolver, tryApi, cancellation.Token);
        }

        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(Invoke);
        Assert.Equal(cancellation.Token, error.CancellationToken);
        Assert.Equal(0, verifier.Calls);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Should_RejectLateCancellation_When_CustomVerifierIgnoresToken(bool useResolver, bool tryApi)
    {
        using var cancellation = new CancellationTokenSource();
        var verifier = new RecordingVerifier { OnCall = cancellation.Cancel };
        Task<VerificationResult> Invoke()
        {
            return InvokeAsync(verifier, useResolver, tryApi, cancellation.Token);
        }

        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(Invoke);
        Assert.Equal(cancellation.Token, error.CancellationToken);
        Assert.Equal(1, verifier.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_PreserveDomainErrorCode_When_CustomVerifierThrows(bool useResolver)
    {
        var verifier = new RecordingVerifier { Failure = new SdJwtException("sensitive backend detail", ErrorCode.KeyIdNotFound) };
        var result = await InvokeAsync(verifier, useResolver, true, default);
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.KeyIdNotFound, result.Errors);
        Assert.DoesNotContain("sensitive backend detail", result.ErrorDetails ?? string.Empty);
        Assert.Equal(1, verifier.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_ThrowOnInvalidResult_When_CustomVerifierReturnsFailure(bool useResolver)
    {
        var result = new VerificationResult(ErrorCode.InvalidSignature, "sensitive token detail");
        var verifier = new RecordingVerifier { Response = result };
        Task<VerificationResult> Invoke()
        {
            return InvokeAsync(verifier, useResolver, false, default);
        }

        var error = await Assert.ThrowsAsync<SdJwtException>(Invoke);
        Assert.Equal(ErrorCode.InvalidSignature, error.ErrorCode);
        Assert.DoesNotContain("sensitive token detail", error.Message);
        Assert.Same(result, await InvokeAsync(verifier, useResolver, true, default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_PropagateUnexpectedFailures_When_UsingTryEntryPoint(bool useResolver)
    {
        var expected = new InvalidOperationException("broken custom implementation");
        var verifier = new RecordingVerifier { Failure = expected };
        Task<VerificationResult> Invoke()
        {
            return InvokeAsync(verifier, useResolver, true, default);
        }

        Assert.Same(expected, await Assert.ThrowsAsync<InvalidOperationException>(Invoke));
    }

    [Fact]
    public async Task Should_ForwardPolicyAndTokenWithoutBlocking_When_CustomVerifierIsAsynchronous()
    {
        var pending = new TaskCompletionSource<VerificationResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var verifier = new RecordingVerifier { Pending = pending.Task };
        using var cancellation = new CancellationTokenSource();
        byte[] key = [1, 2, 3];
        byte[]? Resolve(string _)
        {
            return key;
        }
        KeyResolver resolver = Resolve;
        var operation = verifier.TryVerifyAsync("presentation", resolver, key, HashAlgorithm.Sha384, cancellation.Token);

        Assert.False(operation.IsCompleted);
        Assert.Equal("presentation", verifier.Presentation);
        Assert.Same(resolver, verifier.Resolver);
        Assert.Same(key, verifier.Key);
        Assert.Equal(HashAlgorithm.Sha384, verifier.Hash);
        Assert.Equal(cancellation.Token, verifier.Token);
        pending.SetResult(verifier.Response);
        Assert.Same(verifier.Response, await operation);
        Assert.Equal(1, verifier.Calls);
    }

    [Fact]
    public void Should_ValidateNullArgumentsSynchronously_When_StartingAsyncVerification()
    {
        ISdJwtVerifierAsync verifier = new RecordingVerifier();
        void NullVerifier()
        {
            _ = ((ISdJwtVerifierAsync)null!).TryVerifyAsync("presentation", new byte[32]);
        }
        void NullPresentation()
        {
            _ = verifier.VerifyAsync(null!, new byte[32]);
        }
        void NullKey()
        {
            _ = verifier.TryVerifyAsync("presentation", (byte[])null!);
        }

        Assert.Throws<ArgumentNullException>(NullVerifier);
        Assert.Throws<ArgumentNullException>(NullPresentation);
        Assert.Throws<ArgumentNullException>(NullKey);
    }

    private static Task<VerificationResult> InvokeAsync(ISdJwtVerifierAsync verifier, bool useResolver, bool tryApi, CancellationToken token)
    {
        if (useResolver)
        {
            return tryApi
                ? verifier.TryVerifyAsync("invalid input", (KeyResolver?)null, fallbackKey: [], cancellationToken: token)
                : verifier.VerifyAsync("invalid input", (KeyResolver?)null, fallbackKey: [], cancellationToken: token);
        }

        return tryApi
            ? verifier.TryVerifyAsync("invalid input", [], cancellationToken: token)
            : verifier.VerifyAsync("invalid input", [], cancellationToken: token);
    }

    private static SdJwtVerifier CreateVerifier()
    {
        return SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();
    }

    private static string CreatePresentation(byte[] key, bool includeKeyId)
    {
        var issuer = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("email", "alice@example.test")
            .MakeSelective("email")
            .SignWithHmac(key);
        if (includeKeyId)
        {
            issuer.WithKeyId("key-v1");
        }

        return issuer.Build().ToPresentation("email");
    }

    private sealed class RecordingVerifier : ISdJwtVerifierAsync
    {
        public VerificationResult Response { get; init; } = new(new Dictionary<string, JsonElement> { ["sub"] = JsonSerializer.SerializeToElement("user-123") });
        public Exception? Failure { get; init; }
        public Action? OnCall { get; init; }
        public Task<VerificationResult>? Pending { get; init; }
        public int Calls { get; private set; }
        public string? Presentation { get; private set; }
        public byte[]? Key { get; private set; }
        public KeyResolver? Resolver { get; private set; }
        public HashAlgorithm? Hash { get; private set; }
        public CancellationToken Token { get; private set; }

        public Task<VerificationResult> VerifyPresentationAsync(string presentation, byte[] publicKey, HashAlgorithm? expectedHashAlgorithm = null, CancellationToken cancellationToken = default)
        {
            return Record(presentation, publicKey, null, expectedHashAlgorithm, cancellationToken);
        }

        public Task<VerificationResult> VerifyPresentationAsync(string presentation, KeyResolver? keyResolver, byte[]? fallbackKey = null, HashAlgorithm? expectedHashAlgorithm = null, CancellationToken cancellationToken = default)
        {
            return Record(presentation, fallbackKey, keyResolver, expectedHashAlgorithm, cancellationToken);
        }

        public Task<VerificationResult> TryVerifyPresentationAsync(string presentation, byte[] publicKey, HashAlgorithm? expectedHashAlgorithm = null, CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("The new API must not invoke the legacy Try path.");
        }

        public Task<VerificationResult> TryVerifyPresentationAsync(string presentation, KeyResolver? keyResolver, byte[]? fallbackKey = null, HashAlgorithm? expectedHashAlgorithm = null, CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("The new API must not invoke the legacy Try path.");
        }

        private Task<VerificationResult> Record(string presentation, byte[]? key, KeyResolver? resolver, HashAlgorithm? hash, CancellationToken token)
        {
            Calls++;
            Presentation = presentation;
            Key = key;
            Resolver = resolver;
            Hash = hash;
            Token = token;
            OnCall?.Invoke();
            if (Failure is not null)
            {
                throw Failure;
            }

            return Pending ?? Task.FromResult(Response);
        }
    }
}
