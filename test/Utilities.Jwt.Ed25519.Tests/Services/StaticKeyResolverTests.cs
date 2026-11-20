using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Options;
using Utilities.Jwt.Ed25519.Services;
using MsOptions = Microsoft.Extensions.Options.Options;

namespace Utilities.Jwt.Ed25519.Tests.Services;

/// <summary>
/// Tests for <see cref="StaticKeyResolver"/>.
/// The resolver must not give its key for a token with a different kid when a key ID is set.
/// </summary>
public class StaticKeyResolverTests
{
	[Theory]
	[InlineData(null)]
	[InlineData("any-kid")]
	public async Task ResolvePublicKeyAsync_NoKeyIdInOptions_ReturnsKeyForAnyKid(string? tokenKeyId)
	{
		// Given
		var resolver = new StaticKeyResolver(MsOptions.Create(new StaticValidationKeyOptions { PublicKeyPem = TestData.PublicKeyPem }));

		// When
		var key = await resolver.ResolvePublicKeyAsync(new JwtKeyResolutionContext(tokenKeyId, null, null), CancellationToken.None);

		// Then
		Assert.NotNull(key);
		Assert.Equal(Ed25519KeyLoader.LoadPublicKey(TestData.PublicKeyPem).GetEncoded(), key.PublicKey.GetEncoded());
		Assert.Null(key.ExpectedSubject);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("other")]
	public async Task ResolvePublicKeyAsync_KeyIdInOptionsAndOtherKid_ReturnsNull(string? tokenKeyId)
	{
		// Given
		var options = new StaticValidationKeyOptions { PublicKeyPem = TestData.PublicKeyPem, KeyId = "main" };
		var resolver = new StaticKeyResolver(MsOptions.Create(options));

		// When
		var key = await resolver.ResolvePublicKeyAsync(new JwtKeyResolutionContext(tokenKeyId, null, null), CancellationToken.None);

		// Then
		Assert.Null(key);
	}

	[Fact]
	public async Task ResolvePublicKeyAsync_KeyIdInOptionsAndSameKid_ReturnsKey()
	{
		// Given
		var options = new StaticValidationKeyOptions { PublicKeyPem = TestData.PublicKeyPem, KeyId = "main" };
		var resolver = new StaticKeyResolver(MsOptions.Create(options));

		// When
		var key = await resolver.ResolvePublicKeyAsync(new JwtKeyResolutionContext("main", null, null), CancellationToken.None);

		// Then
		Assert.NotNull(key);
	}
}
