using Utilities.Jwt.Ed25519.Options;
using Utilities.Jwt.Ed25519.Services;
using MsOptions = Microsoft.Extensions.Options.Options;

namespace Utilities.Jwt.Ed25519.Tests.Services;

/// <summary>
/// Tests for <see cref="StaticSigningKeyResolver"/>.
/// The resolver must not sign with its key under a different key ID. Otherwise the kid does not match the key.
/// </summary>
public class StaticSigningKeyResolverTests
{
	[Theory]
	[InlineData(null)]
	[InlineData("main")]
	public async Task ResolveSigningKeyAsync_NullOrSameKeyId_ReturnsKeyWithConfiguredKeyId(string? requestedKeyId)
	{
		// Given
		var options = new StaticSigningKeyOptions { PrivateKeyPem = TestData.PrivateKeyPem, KeyId = "main" };
		var resolver = new StaticSigningKeyResolver(MsOptions.Create(options));

		// When
		var key = await resolver.ResolveSigningKeyAsync(requestedKeyId, CancellationToken.None);

		// Then
		Assert.Equal("main", key.KeyId);
		Assert.Equal(Ed25519KeyLoader.LoadPrivateKey(TestData.PrivateKeyPem).GetEncoded(), key.PrivateKey.GetEncoded());
	}

	[Fact]
	public async Task ResolveSigningKeyAsync_OtherKeyId_ThrowsInvalidOperationException()
	{
		// Given
		var options = new StaticSigningKeyOptions { PrivateKeyPem = TestData.PrivateKeyPem, KeyId = "main" };
		var resolver = new StaticSigningKeyResolver(MsOptions.Create(options));

		// When
		var ex = await Record.ExceptionAsync(async () => await resolver.ResolveSigningKeyAsync("other", CancellationToken.None));

		// Then
		Assert.IsType<InvalidOperationException>(ex);
	}
}
