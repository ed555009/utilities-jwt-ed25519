using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Services;
using Xunit.Abstractions;

namespace Utilities.Jwt.Ed25519.Tests;

/// <summary>
/// Tests for <see cref="JwtService"/>.
/// The validation tests pin the security controls: signature, header, lifetime, and malformed input.
/// A regression in these controls lets a client use an expired, forged, or malformed token.
/// </summary>
public class JwtServiceTests(ITestOutputHelper testOutputHelper)
{
	private readonly ITestOutputHelper _testOutputHelper = testOutputHelper;
	private readonly long _now = 1736152253;
	private readonly long _exp = 1736152313;
	private readonly string _jti = "26eb75d3-b86b-4954-be70-99e7d34f13cb";
	private const string CustomPayloadToken = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJjdXN0b21fY2xhaW0iOiJDdXN0b21DbGFpbVZhbHVlIiwiaXNzIjoidGVzdCIsInN1YiI6InRlc3QiLCJhdWQiOiJ0ZXN0IiwiZXhwIjoxNzM2MTUyMzEzLCJuYmYiOjE3MzYxNTIyNTMsImlhdCI6MTczNjE1MjI1MywianRpIjoiMjZlYjc1ZDMtYjg2Yi00OTU0LWJlNzAtOTllN2QzNGYxM2NiIn0.9xvehbqez-cJWiC8xnYsiI-vxh2rSru1JbNdp3nZYruTJhTp8EvSEQCcnLHEIhLfgp3x5wKQcsAarTxyGtuGCg";
	private readonly string _privateKey = @"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBjirw/3PNIj5F6kfA100R6k2s9Wgb7yxYrVZbDfnOJf
-----END PRIVATE KEY-----
";
	private readonly string _publicKey = @"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFYcbSrDaJytx/y7qxFZQpUGb+GORxSBWY2PrOo5fnIY=
-----END PUBLIC KEY-----
";

	[Fact]
	public void BuildTokenWithCustomPayloadShouldSuccess()
	{
		// Given
		var payload = new CustomPayload
		{
			Subject = "test",
			Issuer = "test",
			Audience = "test",
			Expiration = _exp,
			IssuedAt = _now,
			NotBefore = _now,
			JwtId = _jti,
			CustomClaim = "CustomClaimValue"
		};

		// When
		var token = JwtService.BuildToken(payload, JwtService.LoadPrivateKey(_privateKey));

		// Then
		Assert.Equal(CustomPayloadToken, token);
	}

	[Fact]
	public void BuildTokenWithWrongKeyStringShouldThrow()
	{
		// Given
		var payload = new CustomPayload
		{
			Subject = "test",
			Issuer = "test",
			Audience = "test",
			Expiration = _exp,
			IssuedAt = _now,
			NotBefore = _now,
			JwtId = _jti,
			CustomClaim = "CustomClaimValue"
		};

		// When
		var ex = Assert.Throws<InvalidDataException>(() =>
			JwtService.BuildToken(payload, JwtService.LoadPrivateKey("MC4CAQAwBQYDK2VwBCIEIBjirw", LoadKeyType.String)));

		// Then
		Assert.NotNull(ex);
	}

	[Fact]
	public void BuildTokenWithWrongKeyFileShouldThrow()
	{
		// Given
		var payload = new CustomPayload
		{
			Subject = "test",
			Issuer = "test",
			Audience = "test",
			Expiration = _exp,
			IssuedAt = _now,
			NotBefore = _now,
			JwtId = _jti,
			CustomClaim = "CustomClaimValue"
		};

		// When
		var ex = Assert.Throws<InvalidDataException>(() =>
			JwtService.BuildToken(payload, JwtService.LoadPrivateKey("private_rsa.key", LoadKeyType.File)));

		// Then
		Assert.NotNull(ex);
	}

	[Fact]
	public void ValidateToken_ValidToken_ReturnsTrueAndPayload()
	{
		// Given
		var now = DateTimeOffset.UtcNow;
		var token = JwtService.BuildToken(
			CreatePayload(now.AddHours(1).ToUnixTimeSeconds(), now.AddHours(-1).ToUnixTimeSeconds()),
			JwtService.LoadPrivateKey(_privateKey));

		// When
		var result = JwtService.ValidateToken<CustomPayload>(token, JwtService.LoadPublicKey(_publicKey), out var payload);

		// Then
		Assert.True(result);
		Assert.Equal("CustomClaimValue", payload.CustomClaim);
	}

	[Fact]
	public void ValidateToken_TokenWithoutExpAndNbf_ReturnsTrue()
	{
		// Given
		var token = JwtService.BuildToken(CreatePayload(null, null), JwtService.LoadPrivateKey(_privateKey));

		// When
		var result = JwtService.ValidateToken<CustomPayload>(token, JwtService.LoadPublicKey(_publicKey), out var payload);

		// Then
		Assert.True(result);
		Assert.Equal("CustomClaimValue", payload.CustomClaim);
	}

	[Fact]
	public void ValidateToken_FixedTokenExpiredIn2025_ReturnsFalse()
	{
		// Given
		// CustomPayloadToken has exp 1736152313 (2025-01-06 08:31:53Z).

		// When
		var result = JwtService.ValidateToken<CustomPayload>(
			CustomPayloadToken,
			JwtService.LoadPublicKey(_publicKey),
			out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	[Fact]
	public void ValidateToken_ExpInPast_ReturnsFalse()
	{
		// Given
		var now = DateTimeOffset.UtcNow;
		var token = JwtService.BuildToken(
			CreatePayload(now.AddMinutes(-1).ToUnixTimeSeconds(), now.AddHours(-1).ToUnixTimeSeconds()),
			JwtService.LoadPrivateKey(_privateKey));

		// When
		var result = JwtService.ValidateToken<CustomPayload>(token, JwtService.LoadPublicKey(_publicKey), out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	[Fact]
	public void ValidateToken_NbfInFuture_ReturnsFalse()
	{
		// Given
		var now = DateTimeOffset.UtcNow;
		var token = JwtService.BuildToken(
			CreatePayload(now.AddHours(1).ToUnixTimeSeconds(), now.AddMinutes(1).ToUnixTimeSeconds()),
			JwtService.LoadPrivateKey(_privateKey));

		// When
		var result = JwtService.ValidateToken<CustomPayload>(token, JwtService.LoadPublicKey(_publicKey), out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	[Fact]
	public void ValidateToken_TokenSignedWithOtherKey_ReturnsFalse()
	{
		// Given
		var otherKey = new Ed25519PrivateKeyParameters(new SecureRandom());
		var token = JwtService.BuildToken(CreatePayload(null, null), otherKey);

		// When
		var result = JwtService.ValidateToken<CustomPayload>(token, JwtService.LoadPublicKey(_publicKey), out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	[Fact]
	public void ValidateToken_SignedHeaderWithExtraNumberValue_ReturnsTrue()
	{
		// Given
		var token = Sign("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"x\":1}", "{\"custom_claim\":\"CustomClaimValue\"}");

		// When
		var result = JwtService.ValidateToken<CustomPayload>(token, JwtService.LoadPublicKey(_publicKey), out var payload);

		// Then
		Assert.True(result);
		Assert.Equal("CustomClaimValue", payload.CustomClaim);
	}

	[Theory]
	[MemberData(nameof(MalformedTokens))]
	public void ValidateToken_MalformedToken_ReturnsFalse(string token)
	{
		// Given

		// When
		var result = JwtService.ValidateToken<CustomPayload>(token, JwtService.LoadPublicKey(_publicKey), out var payload);

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
	public void ValidateToken_SignedTokenWithInvalidContent_ReturnsFalse(string header, string body)
	{
		// Given
		// The signature is valid. Only the header or the payload content is not valid.
		var token = Sign(header, body);

		// When
		var result = JwtService.ValidateToken<CustomPayload>(token, JwtService.LoadPublicKey(_publicKey), out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	public static TheoryData<string> MalformedTokens()
	{
		var parts = CustomPayloadToken.Split('.');
		var tamperedPayload = Base64UrlEncode(
			Encoding.UTF8.GetString(JwtService.Base64UrlDecode(parts[1])).Replace("CustomClaimValue", "TamperedValue"));

		return new TheoryData<string>
		{
			"",
			$"{parts[0]}.{parts[1]}",
			$"{parts[0]}.{parts[1]}.{parts[2]}.{parts[2]}",
			$"{Base64UrlEncode("{\"typ\":\"JWT\"}")}.{parts[1]}.{parts[2]}",
			$"{Base64UrlEncode("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"x\":1}")}.{parts[1]}.{parts[2]}",
			$"{parts[0]}.{parts[1]}.@@@@",
			$"{parts[0]}.{Base64UrlEncode("not json")}.{parts[2]}",
			$"{parts[0]}.{tamperedPayload}.{parts[2]}",
			$"{parts[0]}=.{parts[1]}.{parts[2]}",
			$"{parts[0]}.{parts[1]} .{parts[2]}",
			$"{parts[0]}.{parts[1]}.AAAA",
			$"{parts[0]}.{parts[1]}.A"
		};
	}

	private static CustomPayload CreatePayload(long? expiration, long? notBefore) => new()
	{
		Subject = "test",
		Issuer = "test",
		Audience = "test",
		Expiration = expiration,
		NotBefore = notBefore,
		CustomClaim = "CustomClaimValue"
	};

	private string Sign(string header, string body)
	{
		var data = $"{Base64UrlEncode(header)}.{Base64UrlEncode(body)}";
		var bytes = Encoding.UTF8.GetBytes(data);
		var signer = new Ed25519Signer();
		signer.Init(true, JwtService.LoadPrivateKey(_privateKey));
		signer.BlockUpdate(bytes, 0, bytes.Length);

		return $"{data}.{Base64UrlEncode(signer.GenerateSignature())}";
	}

	private static string Base64UrlEncode(string data) =>
		Base64UrlEncode(Encoding.UTF8.GetBytes(data));

	private static string Base64UrlEncode(byte[] data) =>
		Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

	[Fact]
	public void ValidateTokenWithWrongKeyStringShouldThrow()
	{
		// Given

		// When
		var ex = Assert.Throws<InvalidDataException>(() =>
			JwtService.ValidateToken<CustomPayload>(
				CustomPayloadToken,
				JwtService.LoadPublicKey("MCowBQYDK2VwAyEAFYcbSrDaJytx", LoadKeyType.String), out _));

		// Then
		Assert.NotNull(ex);
	}

	[Fact]
	public void ValidateTokenWithWrongKeyFileShouldThrow()
	{
		// Given

		// When
		var ex = Assert.Throws<InvalidDataException>(() =>
			JwtService.ValidateToken<CustomPayload>(
				CustomPayloadToken,
				JwtService.LoadPublicKey("public_rsa.pem", LoadKeyType.File),
				out _));

		// Then
		Assert.NotNull(ex);
	}
}
