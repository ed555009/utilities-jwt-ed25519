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
}
