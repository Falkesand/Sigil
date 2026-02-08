using Sigil.Vault;
using Sigil.Vault.Pkcs11;

namespace Sigil.Vault.Pkcs11.Tests;

public class Pkcs11UriParserTests
{
    [Fact]
    public void Parse_BasicUri_ExtractsTokenAndObject()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:token=MyToken;object=my-key");

        Assert.True(result.IsSuccess);
        Assert.Equal("MyToken", result.Value.Token);
        Assert.Equal("my-key", result.Value.ObjectLabel);
    }

    [Fact]
    public void Parse_FullUri_ExtractsAllPathAttributes()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:token=YubiKey;object=sigil-key;type=private;manufacturer=Yubico;serial=12345678");

        Assert.True(result.IsSuccess);
        Assert.Equal("YubiKey", result.Value.Token);
        Assert.Equal("sigil-key", result.Value.ObjectLabel);
        Assert.Equal("private", result.Value.Type);
        Assert.Equal("Yubico", result.Value.Manufacturer);
        Assert.Equal("12345678", result.Value.Serial);
    }

    [Fact]
    public void Parse_WithQueryAttributes_ExtractsModulePathAndPinValue()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:token=MyHSM;object=key1?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-value=1234");

        Assert.True(result.IsSuccess);
        Assert.Equal("MyHSM", result.Value.Token);
        Assert.Equal("key1", result.Value.ObjectLabel);
        Assert.Equal("/usr/lib/softhsm/libsofthsm2.so", result.Value.ModulePath);
        Assert.Equal("1234", result.Value.PinValue);
    }

    [Fact]
    public void Parse_WithSlotId_ExtractsSlotNumber()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:slot-id=0;object=my-key");

        Assert.True(result.IsSuccess);
        Assert.Equal(0UL, result.Value.SlotId);
        Assert.Equal("my-key", result.Value.ObjectLabel);
    }

    [Fact]
    public void Parse_WithPercentEncoding_DecodesValues()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:token=My%20Token;object=key%2F1");

        Assert.True(result.IsSuccess);
        Assert.Equal("My Token", result.Value.Token);
        Assert.Equal("key/1", result.Value.ObjectLabel);
    }

    [Fact]
    public void Parse_WithId_ExtractsHexEncodedId()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:token=MyToken;id=%01%02%03");

        Assert.True(result.IsSuccess);
        Assert.Equal("MyToken", result.Value.Token);
        Assert.Equal(new byte[] { 1, 2, 3 }, result.Value.Id);
    }

    [Fact]
    public void Parse_TokenOnly_Succeeds()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:token=SomeToken");

        Assert.True(result.IsSuccess);
        Assert.Equal("SomeToken", result.Value.Token);
        Assert.Null(result.Value.ObjectLabel);
    }

    [Fact]
    public void Parse_ObjectOnly_Succeeds()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:object=my-key");

        Assert.True(result.IsSuccess);
        Assert.Equal("my-key", result.Value.ObjectLabel);
        Assert.Null(result.Value.Token);
    }

    [Fact]
    public void Parse_EmptyPath_ReturnsEmptyComponents()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:");

        Assert.True(result.IsSuccess);
        Assert.Null(result.Value.Token);
        Assert.Null(result.Value.ObjectLabel);
    }

    [Fact]
    public void Parse_NullInput_ReturnsFail()
    {
        var result = Pkcs11UriParser.Parse(null!);

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, result.ErrorKind);
    }

    [Fact]
    public void Parse_EmptyInput_ReturnsFail()
    {
        var result = Pkcs11UriParser.Parse("");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, result.ErrorKind);
    }

    [Fact]
    public void Parse_InvalidScheme_ReturnsFail()
    {
        var result = Pkcs11UriParser.Parse("https://example.com");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, result.ErrorKind);
    }

    [Fact]
    public void Parse_CaseInsensitiveScheme_Succeeds()
    {
        var result = Pkcs11UriParser.Parse("PKCS11:token=Test");

        Assert.True(result.IsSuccess);
        Assert.Equal("Test", result.Value.Token);
    }

    [Fact]
    public void Parse_UnknownAttributes_Ignores()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:token=MyToken;unknown=value;object=key1");

        Assert.True(result.IsSuccess);
        Assert.Equal("MyToken", result.Value.Token);
        Assert.Equal("key1", result.Value.ObjectLabel);
    }

    [Fact]
    public void Parse_ModulePathOnly_InQuery()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:token=T?module-path=C%3A%5Clib%5Cpkcs11.dll");

        Assert.True(result.IsSuccess);
        Assert.Equal(@"C:\lib\pkcs11.dll", result.Value.ModulePath);
    }

    [Fact]
    public void Parse_LegacyFormat_LibPathSemicolonSeparated()
    {
        // Alternative format: /path/to/lib.so;token=MyHSM;object=key1
        var result = Pkcs11UriParser.Parse("/usr/lib/softhsm/libsofthsm2.so;token=MyHSM;object=key1");

        Assert.True(result.IsSuccess);
        Assert.Equal("/usr/lib/softhsm/libsofthsm2.so", result.Value.ModulePath);
        Assert.Equal("MyHSM", result.Value.Token);
        Assert.Equal("key1", result.Value.ObjectLabel);
    }

    [Fact]
    public void Parse_WindowsLegacyFormat_LibPathSemicolonSeparated()
    {
        var result = Pkcs11UriParser.Parse(@"C:\Program Files\OpenSC\pkcs11.dll;token=MyCard;object=sign-key");

        Assert.True(result.IsSuccess);
        Assert.Equal(@"C:\Program Files\OpenSC\pkcs11.dll", result.Value.ModulePath);
        Assert.Equal("MyCard", result.Value.Token);
        Assert.Equal("sign-key", result.Value.ObjectLabel);
    }

    [Fact]
    public void Parse_DefaultValues_AreNull()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:token=T");

        Assert.True(result.IsSuccess);
        Assert.Null(result.Value.ObjectLabel);
        Assert.Null(result.Value.ModulePath);
        Assert.Null(result.Value.PinValue);
        Assert.Null(result.Value.Type);
        Assert.Null(result.Value.Id);
        Assert.Null(result.Value.SlotId);
        Assert.Null(result.Value.Manufacturer);
        Assert.Null(result.Value.Serial);
    }

    [Fact]
    public void Parse_MultipleQueryParams_AllExtracted()
    {
        var result = Pkcs11UriParser.Parse("pkcs11:token=T;object=K?module-path=/lib/p11.so&pin-value=secret");

        Assert.True(result.IsSuccess);
        Assert.Equal("/lib/p11.so", result.Value.ModulePath);
        Assert.Equal("secret", result.Value.PinValue);
    }
}
