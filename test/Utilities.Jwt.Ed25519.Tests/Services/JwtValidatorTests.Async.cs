using Moq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Tests.Services;

public partial class JwtValidatorTests
{
	private const string EdDsaHeader = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}";

	[Fact]
	public async Task ValidateTokenAsync_ValidTokenWithKid_ReturnsValidResult()
	{
		// Given
		var token = _signer.BuildToken(TestData.CreatePayload(null, null), _privateKey, "member-1");
		var validator = CreateValidator(ResolverFor("member-1", new JwtVerificationKey(_publicKey)));

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.True(result.IsValid);
		Assert.Equal(JwtValidationError.None, result.Error);
		Assert.Equal("CustomClaimValue", result.Payload?.CustomClaim);
	}

	[Fact]
	public async Task ValidateTokenAsync_Token_GivesKidIssAndSubToResolver()
	{
		// Given
		var token = _signer.BuildToken(TestData.CreatePayload(null, null), _privateKey, "member-1");
		var resolver = new Mock<IJwtKeyResolver>();
		var validator = CreateValidator(resolver);

		// When
		_ = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		resolver.Verify(r => r.ResolvePublicKeyAsync(
			new JwtKeyResolutionContext("member-1", "test", "test"),
			It.IsAny<CancellationToken>()), Times.Once);
	}

	[Fact]
	public async Task ValidateTokenAsync_KeyIdTooLong_ReturnsInvalidKeyIdWithoutResolverCall()
	{
		// Given
		var token = TestData.Sign($"{{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"{new string('a', 129)}\"}}", "{}");
		var resolver = new Mock<IJwtKeyResolver>();
		var validator = CreateValidator(resolver);

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(JwtValidationError.InvalidKeyId, result.Error);
		resolver.Verify(r => r.ResolvePublicKeyAsync(It.IsAny<JwtKeyResolutionContext>(), It.IsAny<CancellationToken>()), Times.Never);
	}

	[Theory]
	[InlineData("\"../keys/admin\"")]
	[InlineData("\"a' OR '1'='1\"")]
	[InlineData("\"\"")]
	[InlineData("1")]
	[InlineData("null")]
	public async Task ValidateTokenAsync_KeyIdNotValid_ReturnsInvalidKeyIdWithoutResolverCall(string kidJson)
	{
		// Given
		var token = TestData.Sign($"{{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":{kidJson}}}", "{}");
		var resolver = new Mock<IJwtKeyResolver>();
		var validator = CreateValidator(resolver);

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(JwtValidationError.InvalidKeyId, result.Error);
		resolver.Verify(r => r.ResolvePublicKeyAsync(It.IsAny<JwtKeyResolutionContext>(), It.IsAny<CancellationToken>()), Times.Never);
	}

	[Fact]
	public async Task ValidateTokenAsync_ResolverReturnsNull_ReturnsKeyNotFound()
	{
		// Given
		var token = _signer.BuildToken(TestData.CreatePayload(null, null), _privateKey, "unknown");
		var validator = CreateValidator(new Mock<IJwtKeyResolver>());

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.False(result.IsValid);
		Assert.Equal(JwtValidationError.KeyNotFound, result.Error);
		Assert.Null(result.Payload);
	}

	[Fact]
	public async Task ValidateTokenAsync_ResolverReturnsOtherKey_ReturnsInvalidSignature()
	{
		// Given
		var token = _signer.BuildToken(TestData.CreatePayload(null, null), _privateKey, "member-1");
		var otherPublicKey = new Ed25519PrivateKeyParameters(new SecureRandom()).GeneratePublicKey();
		var validator = CreateValidator(ResolverFor("member-1", new JwtVerificationKey(otherPublicKey)));

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(JwtValidationError.InvalidSignature, result.Error);
	}

	[Fact]
	public async Task ValidateTokenAsync_SubjectDoesNotMatchExpectedSubject_ReturnsSubjectMismatch()
	{
		// Given
		// Member A signs a token for member B with the key of member A.
		var payload = TestData.CreatePayload(null, null);
		payload.Subject = "member-b";
		var token = _signer.BuildToken(payload, _privateKey, "member-a");
		var validator = CreateValidator(ResolverFor("member-a", new JwtVerificationKey(_publicKey, "member-a")));

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(JwtValidationError.SubjectMismatch, result.Error);
		Assert.Null(result.Payload);
	}

	[Fact]
	public async Task ValidateTokenAsync_SubjectMatchesExpectedSubject_ReturnsValidResult()
	{
		// Given
		var payload = TestData.CreatePayload(null, null);
		payload.Subject = "member-a";
		var token = _signer.BuildToken(payload, _privateKey, "member-a");
		var validator = CreateValidator(ResolverFor("member-a", new JwtVerificationKey(_publicKey, "member-a")));

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.True(result.IsValid);
	}

	[Theory]
	[InlineData("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"crit\":[\"exp\"]}")]
	[InlineData("{\"alg\":\"none\",\"typ\":\"JWT\"}")]
	[InlineData("{\"alg\":\"HS256\",\"typ\":\"JWT\"}")]
	[InlineData("{\"alg\":\"EdDSA\"}")]
	[InlineData("not json")]
	public async Task ValidateTokenAsync_HeaderNotValid_ReturnsInvalidHeader(string header)
	{
		// Given
		var token = TestData.Sign(header, "{}");
		var validator = CreateValidator(ResolverFor(null, new JwtVerificationKey(_publicKey)));

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(JwtValidationError.InvalidHeader, result.Error);
	}

	[Fact]
	public async Task ValidateTokenAsync_HeaderHasJwk_IgnoresJwkKey()
	{
		// Given
		// The attacker signs with an own key and puts the matching public key in the jwk header.
		var attackerKey = new Ed25519PrivateKeyParameters(new SecureRandom());
		var jwk = TestData.Base64UrlEncode(attackerKey.GeneratePublicKey().GetEncoded());
		var header = $"{{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"jwk\":{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{jwk}\"}}}}";
		var token = SignWith(attackerKey, header, "{\"custom_claim\":\"CustomClaimValue\"}");
		var validator = CreateValidator(ResolverFor(null, new JwtVerificationKey(_publicKey)));

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(JwtValidationError.InvalidSignature, result.Error);
	}

	[Theory]
	[InlineData("")]
	[InlineData("a.b")]
	[InlineData("e30.e30.@@@@")]
	public async Task ValidateTokenAsync_MalformedToken_ReturnsInvalidFormat(string token)
	{
		// Given
		var validator = CreateValidator(ResolverFor(null, new JwtVerificationKey(_publicKey)));

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(JwtValidationError.InvalidFormat, result.Error);
	}

	[Theory]
	[InlineData("not json")]
	[InlineData("[]")]
	public async Task ValidateTokenAsync_PayloadNotJsonObject_ReturnsInvalidFormat(string body)
	{
		// Given
		var token = TestData.Sign(EdDsaHeader, body);
		var validator = CreateValidator(ResolverFor(null, new JwtVerificationKey(_publicKey)));

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(JwtValidationError.InvalidFormat, result.Error);
	}

	[Fact]
	public async Task ValidateTokenAsync_NoResolver_ThrowsInvalidOperationException()
	{
		// Given

		// When
		var ex = await Record.ExceptionAsync(async () =>
			await _validator.ValidateTokenAsync<CustomPayload>(TestData.FixedToken, CancellationToken.None));

		// Then
		Assert.IsType<InvalidOperationException>(ex);
	}

	[Fact]
	public void TryValidateToken_TokenWithKid_ReturnsTrue()
	{
		// Given
		var token = _signer.BuildToken(TestData.CreatePayload(null, null), _privateKey, "member-1");

		// When
		var result = _validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.True(result);
		Assert.NotNull(payload);
	}

	[Fact]
	public void TryValidateToken_HeaderHasCrit_ReturnsFalse()
	{
		// Given
		var token = TestData.Sign("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"crit\":[\"exp\"]}", "{}");

		// When
		var result = _validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	private static JwtValidator CreateValidator(Mock<IJwtKeyResolver> resolver) =>
		new(resolver.Object, null, null);

	private static Mock<IJwtKeyResolver> ResolverFor(string? keyId, JwtVerificationKey key)
	{
		var resolver = new Mock<IJwtKeyResolver>();
		_ = resolver
			.Setup(r => r.ResolvePublicKeyAsync(It.Is<JwtKeyResolutionContext>(c => c.KeyId == keyId), It.IsAny<CancellationToken>()))
			.ReturnsAsync(key);

		return resolver;
	}

	private static string SignWith(Ed25519PrivateKeyParameters key, string header, string body)
	{
		var data = $"{TestData.Base64UrlEncode(header)}.{TestData.Base64UrlEncode(body)}";
		var bytes = System.Text.Encoding.ASCII.GetBytes(data);
		var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
		signer.Init(true, key);
		signer.BlockUpdate(bytes, 0, bytes.Length);

		return $"{data}.{TestData.Base64UrlEncode(signer.GenerateSignature())}";
	}
}
