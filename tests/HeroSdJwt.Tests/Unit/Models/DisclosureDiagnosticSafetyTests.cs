using HeroSdJwt.Models;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.Models;

/// <summary>
/// Diagnostic formatting must not expose the values that selective disclosure
/// was designed to keep private, even when a caller logs a model by mistake.
/// </summary>
public class DisclosureDiagnosticSafetyTests
{
    [Fact]
    public void ToString_ObjectProperty_DoesNotRevealSaltOrClaimName()
    {
        using var document = JsonDocument.Parse("\"confidential\"");
        var disclosure = new Disclosure(
            "private-salt-material-not-for-logs",
            "private.medical.condition",
            document.RootElement);

        var diagnostic = disclosure.ToString();

        Assert.Equal("Disclosure(ObjectProperty)", diagnostic);
        Assert.DoesNotContain("private", diagnostic);
        Assert.DoesNotContain("medical", diagnostic);
    }

    [Fact]
    public void ToString_ArrayElement_DoesNotRevealSalt()
    {
        using var document = JsonDocument.Parse("42");
        var disclosure = new Disclosure("private-array-salt-not-for-logs", document.RootElement);

        Assert.Equal("Disclosure(ArrayElement)", disclosure.ToString());
    }

    [Fact]
    public void ToString_DefaultDisclosure_DoesNotThrow()
    {
        Assert.Equal("Disclosure(Uninitialized)", default(Disclosure).ToString());
    }

    [Fact]
    public void ToString_DefaultDigest_DoesNotThrow()
    {
        var diagnostic = default(Digest).ToString();

        Assert.Contains("Digest", diagnostic);
        Assert.Contains("Value=<unset>", diagnostic);
    }
}
