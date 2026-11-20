using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Options;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Tests.Services;

public partial class JwtValidatorTests
{
	private static readonly DateTimeOffset _boundary = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

	[Theory]
	[InlineData(-1, true)]
	[InlineData(0, false)]
	[InlineData(1, false)]
	public async Task ValidateTokenAsync_TimeNearExp_RejectsAtAndAfterExp(int offsetMilliseconds, bool expectedValid)
	{
		// Given
		var validator = CreateTimedValidator(_boundary.AddMilliseconds(offsetMilliseconds), new JwtValidationOptions());
		var token = _signer.BuildToken(TestData.CreatePayload(_boundary.ToUnixTimeSeconds(), null), _privateKey);

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(expectedValid, result.IsValid);
		Assert.Equal(expectedValid ? JwtValidationError.None : JwtValidationError.Expired, result.Error);
	}

	[Theory]
	[InlineData(-1, false)]
	[InlineData(0, true)]
	public async Task ValidateTokenAsync_TimeNearNbf_RejectsBeforeNbf(int offsetMilliseconds, bool expectedValid)
	{
		// Given
		var validator = CreateTimedValidator(_boundary.AddMilliseconds(offsetMilliseconds), new JwtValidationOptions());
		var token = _signer.BuildToken(TestData.CreatePayload(null, _boundary.ToUnixTimeSeconds()), _privateKey);

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(expectedValid, result.IsValid);
		Assert.Equal(expectedValid ? JwtValidationError.None : JwtValidationError.NotYetValid, result.Error);
	}

	[Theory]
	[InlineData(29_999, true)]
	[InlineData(30_000, false)]
	public async Task ValidateTokenAsync_ClockSkewAfterExp_AcceptsUntilSkewEnds(int offsetMilliseconds, bool expectedValid)
	{
		// Given
		var options = new JwtValidationOptions { ClockSkew = TimeSpan.FromSeconds(30) };
		var validator = CreateTimedValidator(_boundary.AddMilliseconds(offsetMilliseconds), options);
		var token = _signer.BuildToken(TestData.CreatePayload(_boundary.ToUnixTimeSeconds(), null), _privateKey);

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(expectedValid, result.IsValid);
	}

	[Theory]
	[InlineData(-30_000, true)]
	[InlineData(-30_001, false)]
	public async Task ValidateTokenAsync_ClockSkewBeforeNbf_AcceptsFromSkewStart(int offsetMilliseconds, bool expectedValid)
	{
		// Given
		var options = new JwtValidationOptions { ClockSkew = TimeSpan.FromSeconds(30) };
		var validator = CreateTimedValidator(_boundary.AddMilliseconds(offsetMilliseconds), options);
		var token = _signer.BuildToken(TestData.CreatePayload(null, _boundary.ToUnixTimeSeconds()), _privateKey);

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(expectedValid, result.IsValid);
	}

	[Fact]
	public async Task ValidateTokenAsync_RequireExpirationAndNoExp_ReturnsMissingExpiration()
	{
		// Given
		var validator = CreateTimedValidator(_boundary, new JwtValidationOptions { RequireExpiration = true });
		var token = _signer.BuildToken(TestData.CreatePayload(null, null), _privateKey);

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(JwtValidationError.MissingExpiration, result.Error);
	}

	[Theory]
	[InlineData("{\"exp\":\"tomorrow\"}")]
	[InlineData("{\"nbf\":\"yesterday\"}")]
	public async Task ValidateTokenAsync_LifetimeClaimNotNumber_ReturnsInvalidFormat(string body)
	{
		// Given
		var validator = CreateTimedValidator(_boundary, new JwtValidationOptions());
		var token = TestData.Sign(EdDsaHeader, body);

		// When
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.Equal(JwtValidationError.InvalidFormat, result.Error);
	}

	[Fact]
	public void TryValidateToken_InjectedClockAfterExp_ReturnsFalse()
	{
		// Given
		var validator = new JwtValidator(null, null, new ManualTimeProvider(_boundary));
		var token = _signer.BuildToken(TestData.CreatePayload(_boundary.ToUnixTimeSeconds(), null), _privateKey);

		// When
		var result = validator.TryValidateToken<CustomPayload>(token, _publicKey, out var payload);

		// Then
		Assert.False(result);
		Assert.Null(payload);
	}

	private JwtValidator CreateTimedValidator(DateTimeOffset now, JwtValidationOptions options) =>
		new(
			ResolverFor(null, new JwtVerificationKey(_publicKey)).Object,
			Microsoft.Extensions.Options.Options.Create(options),
			new ManualTimeProvider(now));
}
