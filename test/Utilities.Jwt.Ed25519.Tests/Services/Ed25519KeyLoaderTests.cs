using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Tests.Services;

/// <summary>
/// Tests for <see cref="Ed25519KeyLoader"/>.
/// The tests pin that the loader accepts only Ed25519 keys. An RSA key must not load as a signing or validation key.
/// </summary>
public class Ed25519KeyLoaderTests
{
	[Fact]
	public void LoadPrivateKey_PemString_ReturnsKeyThatBuildsFixedToken()
	{
		// Given

		// When
		var key = Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem);

		// Then
		Assert.Equal(TestData.FixedToken, new JwtSigner().BuildToken(TestData.CreateFixedPayload(), key));
	}

	[Fact]
	public void LoadPrivateKey_PemFile_ReturnsSameKeyAsPemString()
	{
		// Given
		var expected = Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem);

		// When
		var key = Ed25519KeyLoader.LoadPrivateKey("private.pem", LoadKeyType.File);

		// Then
		Assert.Equal(expected.GetEncoded(), key.GetEncoded());
	}

	[Fact]
	public void LoadPublicKey_PemFile_ReturnsSameKeyAsPemString()
	{
		// Given
		var expected = Ed25519KeyLoader.LoadPublicKey(TestData.PublicKeyPem);

		// When
		var key = Ed25519KeyLoader.LoadPublicKey("public.pem", LoadKeyType.File);

		// Then
		Assert.Equal(expected.GetEncoded(), key.GetEncoded());
	}

	[Fact]
	public void LoadPrivateKey_InvalidPemString_ThrowsInvalidDataException()
	{
		// Given

		// When
		var ex = Record.Exception(() => Ed25519KeyLoader.LoadPrivateKey("MC4CAQAwBQYDK2VwBCIEIBjirw"));

		// Then
		Assert.IsType<InvalidDataException>(ex);
	}

	[Fact]
	public void LoadPrivateKey_RsaKeyFile_ThrowsInvalidDataException()
	{
		// Given

		// When
		var ex = Record.Exception(() => Ed25519KeyLoader.LoadPrivateKey("private_rsa.key", LoadKeyType.File));

		// Then
		Assert.IsType<InvalidDataException>(ex);
	}

	[Fact]
	public void LoadPublicKey_InvalidPemString_ThrowsInvalidDataException()
	{
		// Given

		// When
		var ex = Record.Exception(() => Ed25519KeyLoader.LoadPublicKey("MCowBQYDK2VwAyEAFYcbSrDaJytx"));

		// Then
		Assert.IsType<InvalidDataException>(ex);
	}

	[Fact]
	public void LoadPublicKey_RsaKeyFile_ThrowsInvalidDataException()
	{
		// Given

		// When
		var ex = Record.Exception(() => Ed25519KeyLoader.LoadPublicKey("public_rsa.pem", LoadKeyType.File));

		// Then
		Assert.IsType<InvalidDataException>(ex);
	}

	[Fact]
	public void LoadPublicKey_PrivateKeyPem_ThrowsInvalidDataException()
	{
		// Given

		// When
		var ex = Record.Exception(() => Ed25519KeyLoader.LoadPublicKey(TestData.PrivateKeyPem));

		// Then
		Assert.IsType<InvalidDataException>(ex);
	}
}
