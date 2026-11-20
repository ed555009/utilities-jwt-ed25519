using Moq;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Tests.Services;

/// <summary>
/// Tests for <see cref="JwtSigner"/>.
/// The fixed token test pins the token format. Version 8.0.973 built the same token,
/// so a change of the header, the JSON output, or the signature makes the test fail.
/// </summary>
public class JwtSignerTests
{
	private readonly JwtSigner _signer = new();
	private readonly JwtValidator _validator = new();

	[Fact]
	public void BuildToken_FixedPayload_ReturnsFixedToken()
	{
		// Given
		var payload = TestData.CreateFixedPayload();

		// When
		var token = _signer.BuildToken(payload, Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem));

		// Then
		Assert.Equal(TestData.FixedToken, token);
	}

	[Fact]
	public void BuildToken_NullClaims_OmitsNullClaims()
	{
		// Given
		var payload = TestData.CreatePayload(null, null);

		// When
		var token = _signer.BuildToken(payload, Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem));

		// Then
		Assert.True(Base64Url.TryDecode(token.Split('.')[1], out var json));
		Assert.Equal(
			"{\"custom_claim\":\"CustomClaimValue\",\"iss\":\"test\",\"sub\":\"test\",\"aud\":\"test\"}",
			System.Text.Encoding.UTF8.GetString(json));
	}

	[Fact]
	public void BuildToken_ValidPayload_BuildsTokenThatValidatorAccepts()
	{
		// Given
		var now = DateTimeOffset.UtcNow;
		var payload = TestData.CreatePayload(now.AddHours(1).ToUnixTimeSeconds(), now.AddHours(-1).ToUnixTimeSeconds());

		// When
		var token = _signer.BuildToken(payload, Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem));

		// Then
		Assert.True(_validator.TryValidateToken<CustomPayload>(token, Ed25519KeyLoader.LoadPublicKey(TestData.PublicKeyPem), out var result));
		Assert.Equal("CustomClaimValue", result.CustomClaim);
	}

	[Fact]
	public void BuildToken_KeyId_WritesKidToHeader()
	{
		// Given
		var payload = TestData.CreatePayload(null, null);

		// When
		var token = _signer.BuildToken(payload, Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem), "member-1.v2");

		// Then
		Assert.Equal(TestData.Base64UrlEncode("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"member-1.v2\"}"), token.Split('.')[0]);
	}

	[Theory]
	[InlineData("")]
	[InlineData("../admin")]
	[InlineData("a b")]
	public void BuildToken_InvalidKeyId_ThrowsArgumentException(string keyId)
	{
		// Given
		var payload = TestData.CreatePayload(null, null);

		// When
		var ex = Record.Exception(() => _signer.BuildToken(payload, Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem), keyId));

		// Then
		Assert.Equal("keyId", Assert.IsType<ArgumentException>(ex).ParamName);
	}

	[Fact]
	public async Task BuildTokenAsync_ResolverReturnsKeyId_WritesSameKeyIdToHeader()
	{
		// Given
		var resolver = new Mock<IJwtSigningKeyResolver>();
		_ = resolver
			.Setup(r => r.ResolveSigningKeyAsync(null, It.IsAny<CancellationToken>()))
			.ReturnsAsync(new JwtSigningKey("current.v3", Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem)));
		var signer = new JwtSigner(resolver.Object);

		// When
		var token = await signer.BuildTokenAsync(TestData.CreatePayload(null, null), null, CancellationToken.None);

		// Then
		Assert.Equal(TestData.Base64UrlEncode("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"current.v3\"}"), token.Split('.')[0]);
	}

	[Fact]
	public async Task BuildTokenAsync_RequestedKeyId_PassesKeyIdToResolver()
	{
		// Given
		var resolver = new Mock<IJwtSigningKeyResolver>();
		_ = resolver
			.Setup(r => r.ResolveSigningKeyAsync("tenant:42", It.IsAny<CancellationToken>()))
			.ReturnsAsync(new JwtSigningKey("tenant:42", Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem)));
		var signer = new JwtSigner(resolver.Object);

		// When
		_ = await signer.BuildTokenAsync(TestData.CreatePayload(null, null), "tenant:42", CancellationToken.None);

		// Then
		resolver.Verify(r => r.ResolveSigningKeyAsync("tenant:42", It.IsAny<CancellationToken>()), Times.Once);
	}

	[Fact]
	public async Task BuildTokenAsync_NoResolver_ThrowsInvalidOperationException()
	{
		// Given

		// When
		var ex = await Record.ExceptionAsync(async () =>
			await _signer.BuildTokenAsync(TestData.CreatePayload(null, null), null, CancellationToken.None));

		// Then
		Assert.IsType<InvalidOperationException>(ex);
	}
}
