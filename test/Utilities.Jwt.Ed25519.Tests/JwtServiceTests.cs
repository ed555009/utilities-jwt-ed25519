using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Services;
using Xunit.Abstractions;

namespace Utilities.Jwt.Ed25519.Tests;

public class JwtServiceTests(ITestOutputHelper testOutputHelper)
{
	private readonly ITestOutputHelper _testOutputHelper = testOutputHelper;
	private readonly long _now = 1736152253;
	private readonly long _exp = 1736152313;
	private readonly string _jti = "26eb75d3-b86b-4954-be70-99e7d34f13cb";
	private readonly string _customPayloadToken = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJjdXN0b21fY2xhaW0iOiJDdXN0b21DbGFpbVZhbHVlIiwiaXNzIjoidGVzdCIsInN1YiI6InRlc3QiLCJhdWQiOiJ0ZXN0IiwiZXhwIjoxNzM2MTUyMzEzLCJuYmYiOjE3MzYxNTIyNTMsImlhdCI6MTczNjE1MjI1MywianRpIjoiMjZlYjc1ZDMtYjg2Yi00OTU0LWJlNzAtOTllN2QzNGYxM2NiIn0.9xvehbqez-cJWiC8xnYsiI-vxh2rSru1JbNdp3nZYruTJhTp8EvSEQCcnLHEIhLfgp3x5wKQcsAarTxyGtuGCg";
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
		Assert.Equal(_customPayloadToken, token);
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
	public void ValidateTokenWithCustomPayloadShouldSuccess()
	{
		// Given

		// When
		var result = JwtService.ValidateToken<CustomPayload>(
			_customPayloadToken,
			JwtService.LoadPublicKey(_publicKey),
			out var payload);

		// Then
		Assert.True(result);
		Assert.Equal("CustomClaimValue", payload.CustomClaim);
	}

	[Fact]
	public void ValidateTokenWithWrongKeyStringShouldThrow()
	{
		// Given

		// When
		var ex = Assert.Throws<InvalidDataException>(() =>
			JwtService.ValidateToken<CustomPayload>(
				_customPayloadToken,
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
				_customPayloadToken,
				JwtService.LoadPublicKey("public_rsa.pem", LoadKeyType.File),
				out _));

		// Then
		Assert.NotNull(ex);
	}
}
