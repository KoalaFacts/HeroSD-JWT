using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Unit.Exceptions;

/// <summary>
/// Tests for the security-signalling exceptions <see cref="ReplayAttackException"/> and
/// <see cref="TokenRevokedException"/>, covering every constructor overload and the
/// reason/error-code mapping that callers rely on to distinguish failure causes.
/// </summary>
public class ReplayAndRevocationExceptionTests
{
    // ---- ReplayAttackException ----

    [Fact]
    public void ReplayAttack_DefaultMessage_IncludesJtiAndIssuer()
    {
        var ex = new ReplayAttackException("jti-1", "https://issuer");

        Assert.Equal("jti-1", ex.Jti);
        Assert.Equal("https://issuer", ex.Issuer);
        Assert.Equal(ErrorCode.ReplayAttack, ex.ErrorCode);
        Assert.Contains("jti-1", ex.Message);
        Assert.Contains("https://issuer", ex.Message);
        Assert.True(ex.DetectedAt <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public void ReplayAttack_CustomMessage_IsUsed()
    {
        var ex = new ReplayAttackException("jti-1", "issuer", "custom message");

        Assert.Equal("custom message", ex.Message);
        Assert.Equal(ErrorCode.ReplayAttack, ex.ErrorCode);
    }

    [Fact]
    public void ReplayAttack_WithInnerException_PreservesInner()
    {
        var inner = new InvalidOperationException("cache down");
        var ex = new ReplayAttackException("jti-1", "issuer", "wrapped", inner);

        Assert.Same(inner, ex.InnerException);
        Assert.Equal("wrapped", ex.Message);
        Assert.Equal(ErrorCode.ReplayAttack, ex.ErrorCode);
    }

    [Fact]
    public void ReplayAttack_WithNullJtiOrIssuer_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new ReplayAttackException(null!, "issuer"));
        Assert.Throws<ArgumentNullException>(() => new ReplayAttackException("jti", null!));
    }

    // ---- TokenRevokedException ----

    [Fact]
    public void TokenRevoked_ByJti_SetsJtiReasonAndCode()
    {
        var ex = new TokenRevokedException("jti-42");

        Assert.Equal("jti-42", ex.Jti);
        Assert.Null(ex.KeyId);
        Assert.Null(ex.UserId);
        Assert.Equal(RevocationReason.JtiRevoked, ex.Reason);
        Assert.Equal(ErrorCode.TokenRevoked, ex.ErrorCode);
    }

    [Fact]
    public void TokenRevoked_ByKey_SetsKeyIdReasonAndCode()
    {
        var ex = new TokenRevokedException("key-1", RevocationReason.KeyRevoked);

        Assert.Equal("key-1", ex.KeyId);
        Assert.Equal(RevocationReason.KeyRevoked, ex.Reason);
        Assert.Equal(ErrorCode.TokenRevokedByKey, ex.ErrorCode);
    }

    [Theory]
    [InlineData(RevocationReason.JtiRevoked)]
    [InlineData(RevocationReason.UserRevoked)]
    public void TokenRevoked_ByKey_WithWrongReason_Throws(RevocationReason wrongReason)
    {
        var ex = Assert.Throws<ArgumentException>(() => new TokenRevokedException("key-1", wrongReason));
        Assert.Equal("reason", ex.ParamName);
    }

    [Fact]
    public void TokenRevoked_ByUser_SetsUserIdJtiReasonAndCode()
    {
        var ex = new TokenRevokedException("user-7", RevocationReason.UserRevoked, "jti-99");

        Assert.Equal("user-7", ex.UserId);
        Assert.Equal("jti-99", ex.Jti);
        Assert.Equal(RevocationReason.UserRevoked, ex.Reason);
        Assert.Equal(ErrorCode.TokenRevokedByUser, ex.ErrorCode);
    }

    [Theory]
    [InlineData(RevocationReason.JtiRevoked)]
    [InlineData(RevocationReason.KeyRevoked)]
    public void TokenRevoked_ByUser_WithWrongReason_Throws(RevocationReason wrongReason)
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new TokenRevokedException("user-7", wrongReason, jti: null));
        Assert.Equal("reason", ex.ParamName);
    }
}
