using HeroSdJwt.Common;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for EcPublicKeyConverter (internal class).
/// Validates RFC 7517 JWK creation and parsing for ECDSA P-256 keys.
/// </summary>
public class JwkHelperTests
{
    private readonly IEcPublicKeyConverter _converter = new EcPublicKeyConverter();

    [Fact]
    public void CreateEcPublicKeyJwk_WithValidP256Key_ReturnsCorrectJwk()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        // Act
        var jwk = _converter.ToJwk(publicKey);

        // Assert
        Assert.Equal("EC", jwk["kty"]);
        Assert.Equal("P-256", jwk["crv"]);
        Assert.True(jwk.ContainsKey("x"));
        Assert.True(jwk.ContainsKey("y"));
    }

    [Fact]
    public void CreateEcPublicKeyJwk_WithNullKey_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _converter.ToJwk(null!));
    }

    [Fact]
    public void CreateEcPublicKeyJwk_WithInvalidKeyFormat_ThrowsArgumentException()
    {
        // Arrange
        var invalidKey = new byte[] { 0x00, 0x01, 0x02 };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _converter.ToJwk(invalidKey));
        Assert.Contains("Invalid ECDSA public key", exception.Message);
    }

    [Fact]
    public void CreateEcPublicKeyJwk_WithNonP256Key_ThrowsArgumentException()
    {
        // Arrange - Use P-384 instead of P-256
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _converter.ToJwk(publicKey));
        Assert.Contains("P-256", exception.Message);
    }

    [Fact]
    public void CreateEcPublicKeyJwk_XAndYCoordinatesAreBase64Url()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        // Act
        var jwk = _converter.ToJwk(publicKey);

        // Assert
        var x = jwk["x"].ToString()!;
        var y = jwk["y"].ToString()!;

        // Base64url should not contain +, /, =
        Assert.DoesNotContain("+", x);
        Assert.DoesNotContain("/", x);
        Assert.DoesNotContain("=", x);
        Assert.DoesNotContain("+", y);
        Assert.DoesNotContain("/", y);
        Assert.DoesNotContain("=", y);

        // Should be valid base64url
        Assert.Matches("^[A-Za-z0-9_-]+$", x);
        Assert.Matches("^[A-Za-z0-9_-]+$", y);
    }

    [Fact]
    public void ParseEcPublicKeyJwk_WithValidJwk_ReturnsPublicKey()
    {
        // Arrange
        var jwkJson = """
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        }
        """;
        var jwk = JsonDocument.Parse(jwkJson).RootElement;

        // Act
        var publicKey = _converter.FromJwk(jwk);

        // Assert
        Assert.NotNull(publicKey);
        Assert.NotEmpty(publicKey);

        // Should be importable as ECDSA key
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
        Assert.Equal(256, ecdsa.KeySize); // P-256
    }

    [Fact]
    public void ParseEcPublicKeyJwk_WithMissingKty_ThrowsArgumentException()
    {
        // Arrange
        var jwkJson = """
        {
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        }
        """;
        var jwk = JsonDocument.Parse(jwkJson).RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _converter.FromJwk(jwk));
        Assert.Contains("kty", exception.Message);
    }

    [Fact]
    public void ParseEcPublicKeyJwk_WithWrongKty_ThrowsArgumentException()
    {
        // Arrange
        var jwkJson = """
        {
            "kty": "RSA",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        }
        """;
        var jwk = JsonDocument.Parse(jwkJson).RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _converter.FromJwk(jwk));
        Assert.Contains("EC", exception.Message);
    }

    [Fact]
    public void ParseEcPublicKeyJwk_WithUnsupportedCurve_ThrowsArgumentException()
    {
        // Arrange
        var jwkJson = """
        {
            "kty": "EC",
            "crv": "P-384",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        }
        """;
        var jwk = JsonDocument.Parse(jwkJson).RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _converter.FromJwk(jwk));
        Assert.Contains("P-256", exception.Message);
    }

    [Fact]
    public void ParseEcPublicKeyJwk_WithMissingX_ThrowsArgumentException()
    {
        // Arrange
        var jwkJson = """
        {
            "kty": "EC",
            "crv": "P-256",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        }
        """;
        var jwk = JsonDocument.Parse(jwkJson).RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _converter.FromJwk(jwk));
        Assert.Contains("x", exception.Message);
    }

    [Fact]
    public void ParseEcPublicKeyJwk_WithMissingY_ThrowsArgumentException()
    {
        // Arrange
        var jwkJson = """
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis"
        }
        """;
        var jwk = JsonDocument.Parse(jwkJson).RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _converter.FromJwk(jwk));
        Assert.Contains("y", exception.Message);
    }

    [Fact]
    public void ParseEcPublicKeyJwk_WithInvalidBase64Url_ThrowsArgumentException()
    {
        // Arrange
        var jwkJson = """
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "not-valid-base64url!!!",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        }
        """;
        var jwk = JsonDocument.Parse(jwkJson).RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _converter.FromJwk(jwk));
        Assert.Contains("base64url", exception.Message);
    }

    [Fact]
    public void ParseEcPublicKeyJwk_WithWrongCoordinateSize_ThrowsArgumentException()
    {
        // Arrange - Use 16 bytes instead of 32
        var shortCoordinate = Base64UrlEncoder.Encode(new byte[16]);
        var jwkJson = $$"""
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "{{shortCoordinate}}",
            "y": "{{shortCoordinate}}"
        }
        """;
        var jwk = JsonDocument.Parse(jwkJson).RootElement;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _converter.FromJwk(jwk));
        Assert.Contains("32 bytes", exception.Message);
    }

    [Fact]
    public void CreateAndParse_RoundTrip_PreservesKey()
    {
        // Arrange
        using var originalEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var originalPublicKey = originalEcdsa.ExportSubjectPublicKeyInfo();

        // Act - Create JWK
        var jwk = _converter.ToJwk(originalPublicKey);

        // Act - Convert to JSON and parse back
        var jwkJson = JsonSerializer.Serialize(jwk);
        var jwkElement = JsonDocument.Parse(jwkJson).RootElement;
        var parsedPublicKey = _converter.FromJwk(jwkElement);

        // Assert - Keys should be equivalent
        using var originalEcdsaForExport = ECDsa.Create();
        originalEcdsaForExport.ImportSubjectPublicKeyInfo(originalPublicKey, out _);
        var originalParams = originalEcdsaForExport.ExportParameters(false);

        using var parsedEcdsa = ECDsa.Create();
        parsedEcdsa.ImportSubjectPublicKeyInfo(parsedPublicKey, out _);
        var parsedParams = parsedEcdsa.ExportParameters(false);

        Assert.Equal(originalParams.Q.X, parsedParams.Q.X);
        Assert.Equal(originalParams.Q.Y, parsedParams.Q.Y);
    }

    [Fact]
    public void ParseEcPublicKeyJwkObject_WithJsonElement_Works()
    {
        // Arrange
        var jwkJson = """
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        }
        """;
        var jwkElement = JsonDocument.Parse(jwkJson).RootElement;

        // Act
        var publicKey = _converter.FromJwkObject(jwkElement);

        // Assert
        Assert.NotNull(publicKey);
        Assert.NotEmpty(publicKey);
    }

    [Fact]
    public void ParseEcPublicKeyJwkObject_WithDictionary_Works()
    {
        // Arrange
        var jwkDict = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            ["y"] = "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        };

        // Act
        var publicKey = _converter.FromJwkObject(jwkDict);

        // Assert
        Assert.NotNull(publicKey);
        Assert.NotEmpty(publicKey);
    }

    [Fact]
    public void ParseEcPublicKeyJwkObject_WithInvalidType_ThrowsArgumentException()
    {
        // Arrange
        var invalidObject = "not a JWK";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _converter.FromJwkObject(invalidObject));
        Assert.Contains("JsonElement or Dictionary", exception.Message);
    }

}
