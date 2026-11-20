using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Tests.Services;

/// <summary>
/// Tests for <see cref="JwtValidator"/>.
/// The tests pin the security controls: signature, header, lifetime, and malformed input.
/// A regression in these controls lets a client use an expired, forged, or malformed token.
/// </summary>
public class JwtValidatorTests
{
	private readonly JwtSigner _signer = new();
	private readonly JwtValidator _validator = new();
	private readonly Ed25519PrivateKeyParameters _privateKey = Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem);
	private readonly Ed25519PublicKeyParameters _publicKey = Ed25519KeyLoader.LoadPublicKey(TestData.PublicKeyPem);

	[Fact]
	public void TryValidateToken_ValidToken_ReturnsTrueAndPayload()
	{
		// Given
		var now = DateTimeOffset.UtcNow;
		var token = _signer.BuildToken(
			TestData.CreatePayload(now.AddHours(1).ToUnixTimeSeconds(), now.AddHours(-1).ToUnixTimeSeconds()),
			_privateKey);

		// When
		var result = _validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.True(result);
		Assert.NotNull(payload);
		Assert.Equal("CustomClaimValue", payload.CustomClaim);
	}

	[Fact]
	public void TryValidateToken_TokenWithoutExpAndNbf_ReturnsTrue()
	{
		// Given
		var token = _signer.BuildToken(TestData.CreatePayload(null, null), _privateKey);

		// When
		var result = _validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.True(result);
		Assert.NotNull(payload);
		Assert.Equal("CustomClaimValue", payload.CustomClaim);
	}

	[Fact]
	public void TryValidateToken_FixedTokenExpiredIn2025_ReturnsFalse()
	{
		// Given
		// TestData.FixedToken has exp 1736152313 (2025-01-06 08:31:53Z).

		// When
		var result = _validator.TryValidateToken<CustomPayload>(TestData.FixedToken, _publicKey, out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	[Fact]
	public void TryValidateToken_ExpInPast_ReturnsFalse()
	{
		// Given
		var now = DateTimeOffset.UtcNow;
		var token = _signer.BuildToken(
			TestData.CreatePayload(now.AddMinutes(-1).ToUnixTimeSeconds(), now.AddHours(-1).ToUnixTimeSeconds()),
			_privateKey);

		// When
		var result = _validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	[Fact]
	public void TryValidateToken_NbfInFuture_ReturnsFalse()
	{
		// Given
		var now = DateTimeOffset.UtcNow;
		var token = _signer.BuildToken(
			TestData.CreatePayload(now.AddHours(1).ToUnixTimeSeconds(), now.AddMinutes(1).ToUnixTimeSeconds()),
			_privateKey);

		// When
		var result = _validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	[Fact]
	public void TryValidateToken_TokenSignedWithOtherKey_ReturnsFalse()
	{
		// Given
		var otherKey = new Ed25519PrivateKeyParameters(new SecureRandom());
		var token = _signer.BuildToken(TestData.CreatePayload(null, null), otherKey);

		// When
		var result = _validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	[Fact]
	public void TryValidateToken_SignedHeaderWithExtraNumberValue_ReturnsTrue()
	{
		// Given
		var token = TestData.Sign("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"x\":1}", "{\"custom_claim\":\"CustomClaimValue\"}");

		// When
		var result = _validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.True(result);
		Assert.NotNull(payload);
		Assert.Equal("CustomClaimValue", payload.CustomClaim);
	}

	[Theory]
	[MemberData(nameof(MalformedTokens))]
	public void TryValidateToken_MalformedToken_ReturnsFalse(string token)
	{
		// Given

		// When
		var result = _validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	[Theory]
	[InlineData("{\"typ\":\"JWT\"}", "{}")]
	[InlineData("{\"alg\":\"none\",\"typ\":\"JWT\"}", "{}")]
	[InlineData("{\"alg\":\"EdDSA\"}", "{}")]
	[InlineData("{\"alg\":1,\"typ\":\"JWT\"}", "{}")]
	[InlineData("[]", "{}")]
	[InlineData("not json", "{}")]
	[InlineData("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", "not json")]
	[InlineData("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", "[]")]
	[InlineData("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", "null")]
	[InlineData("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", "{\"exp\":\"tomorrow\"}")]
	[InlineData("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", "{\"exp\":null}")]
	[InlineData("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", "{\"nbf\":\"yesterday\"}")]
	[InlineData("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", "{\"custom_claim\":1}")]
	public void TryValidateToken_SignedTokenWithInvalidContent_ReturnsFalse(string header, string body)
	{
		// Given
		// The signature is valid. Only the header or the payload content is not valid.
		var token = TestData.Sign(header, body);

		// When
		var result = _validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	public static TheoryData<string> MalformedTokens()
	{
		var parts = TestData.FixedToken.Split('.');
		Assert.True(Base64Url.TryDecode(parts[1], out var payloadBytes));
		var tamperedPayload = TestData.Base64UrlEncode(
			Encoding.UTF8.GetString(payloadBytes).Replace("CustomClaimValue", "TamperedValue"));

		return new TheoryData<string>
		{
			"",
			$"{parts[0]}.{parts[1]}",
			$"{parts[0]}.{parts[1]}.{parts[2]}.{parts[2]}",
			$"{TestData.Base64UrlEncode("{\"typ\":\"JWT\"}")}.{parts[1]}.{parts[2]}",
			$"{TestData.Base64UrlEncode("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"x\":1}")}.{parts[1]}.{parts[2]}",
			$"{parts[0]}.{parts[1]}.@@@@",
			$"{parts[0]}.{TestData.Base64UrlEncode("not json")}.{parts[2]}",
			$"{parts[0]}.{tamperedPayload}.{parts[2]}",
			$"{parts[0]}=.{parts[1]}.{parts[2]}",
			$"{parts[0]}.{parts[1]} .{parts[2]}",
			$"{parts[0]}.{parts[1]}.AAAA",
			$"{parts[0]}.{parts[1]}.A"
		};
	}
}
