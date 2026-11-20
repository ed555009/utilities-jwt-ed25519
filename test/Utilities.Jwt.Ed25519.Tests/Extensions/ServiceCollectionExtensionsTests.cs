using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Utilities.Jwt.Ed25519.Extensions;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Tests.Extensions;

/// <summary>
/// Tests for <see cref="ServiceCollectionExtensions"/> and <see cref="JwtEd25519Builder"/>.
/// The tests pin the startup checks: a host with a bad key or a bad option must stop at startup,
/// and the failure message must not contain the key.
/// </summary>
public class ServiceCollectionExtensionsTests
{
	[Fact]
	public async Task AddJwtEd25519_StaticSigningAndValidation_RoundTripsToken()
	{
		// Given
		var services = new ServiceCollection();
		_ = services.AddJwtEd25519()
			.AddSigning(o => { o.PrivateKeyPem = TestData.PrivateKeyPem; o.KeyId = "main"; })
			.AddValidation(o => { o.PublicKeyPem = TestData.PublicKeyPem; o.KeyId = "main"; });
		using var provider = services.BuildServiceProvider();
		provider.GetRequiredService<IStartupValidator>().Validate();
		using var scope = provider.CreateScope();
		var signer = scope.ServiceProvider.GetRequiredService<IJwtSigner>();
		var validator = scope.ServiceProvider.GetRequiredService<IJwtValidator>();

		// When
		var token = await signer.BuildTokenAsync(TestData.CreatePayload(null, null), null, CancellationToken.None);
		var result = await validator.ValidateTokenAsync<CustomPayload>(token, CancellationToken.None);

		// Then
		Assert.True(result.IsValid);
		Assert.Equal("CustomClaimValue", result.Payload?.CustomClaim);
	}

	[Fact]
	public void AddSigning_PemNotEd25519_FailsAtStartupWithoutKeyInMessage()
	{
		// Given
		const string rsaPem = "-----BEGIN PRIVATE KEY-----\nNOT-AN-ED25519-KEY\n-----END PRIVATE KEY-----";
		var services = new ServiceCollection();
		_ = services.AddJwtEd25519().AddSigning(o => o.PrivateKeyPem = rsaPem);
		using var provider = services.BuildServiceProvider();

		// When
		var ex = Record.Exception(() => provider.GetRequiredService<IStartupValidator>().Validate());

		// Then
		var failure = Assert.IsType<OptionsValidationException>(ex);
		Assert.Contains("PrivateKeyPem is not an Ed25519 key in PEM format.", failure.Failures);
		Assert.DoesNotContain("NOT-AN-ED25519-KEY", failure.Message);
	}

	[Fact]
	public void AddValidation_EmptyPem_FailsAtStartup()
	{
		// Given
		var services = new ServiceCollection();
		_ = services.AddJwtEd25519().AddValidation(o => o.PublicKeyPem = "");
		using var provider = services.BuildServiceProvider();

		// When
		var ex = Record.Exception(() => provider.GetRequiredService<IStartupValidator>().Validate());

		// Then
		Assert.IsType<OptionsValidationException>(ex);
	}

	[Fact]
	public void AddValidation_KeyIdNotValid_FailsAtStartup()
	{
		// Given
		var services = new ServiceCollection();
		_ = services.AddJwtEd25519().AddValidation(o => { o.PublicKeyPem = TestData.PublicKeyPem; o.KeyId = "../admin"; });
		using var provider = services.BuildServiceProvider();

		// When
		var ex = Record.Exception(() => provider.GetRequiredService<IStartupValidator>().Validate());

		// Then
		Assert.IsType<OptionsValidationException>(ex);
	}

	[Theory]
	[InlineData(-1)]
	[InlineData(301)]
	public void ConfigureValidation_ClockSkewOutOfRange_FailsAtStartup(int seconds)
	{
		// Given
		var services = new ServiceCollection();
		_ = services.AddJwtEd25519().ConfigureValidation(o => o.ClockSkew = TimeSpan.FromSeconds(seconds));
		using var provider = services.BuildServiceProvider();

		// When
		var ex = Record.Exception(() => provider.GetRequiredService<IStartupValidator>().Validate());

		// Then
		Assert.IsType<OptionsValidationException>(ex);
	}

	[Fact]
	public void AddValidation_CustomResolver_RegistersResolverAsScoped()
	{
		// Given
		var services = new ServiceCollection();

		// When
		_ = services.AddJwtEd25519().AddValidation<NullKeyResolver>();

		// Then
		var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IJwtKeyResolver));
		Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
		Assert.Equal(typeof(NullKeyResolver), descriptor.ImplementationType);
	}

	[Fact]
	public void AddSigning_CustomResolverAfterStaticKey_ReplacesStaticResolver()
	{
		// Given
		var services = new ServiceCollection();

		// When
		_ = services.AddJwtEd25519()
			.AddSigning(o => o.PrivateKeyPem = TestData.PrivateKeyPem)
			.AddSigning<NullSigningKeyResolver>();

		// Then
		var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IJwtSigningKeyResolver));
		Assert.Equal(typeof(NullSigningKeyResolver), descriptor.ImplementationType);
		Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
	}

	[Fact]
	public void AddJwtEd25519_CalledTwice_RegistersOneSignerAndOneValidator()
	{
		// Given
		var services = new ServiceCollection();

		// When
		_ = services.AddJwtEd25519();
		_ = services.AddJwtEd25519();

		// Then
		_ = Assert.Single(services, d => d.ServiceType == typeof(IJwtSigner));
		_ = Assert.Single(services, d => d.ServiceType == typeof(IJwtValidator));
	}

	private sealed class NullKeyResolver : IJwtKeyResolver
	{
		public ValueTask<JwtVerificationKey?> ResolvePublicKeyAsync(JwtKeyResolutionContext context, CancellationToken cancellationToken) =>
			new((JwtVerificationKey?)null);
	}

	private sealed class NullSigningKeyResolver : IJwtSigningKeyResolver
	{
		public ValueTask<JwtSigningKey> ResolveSigningKeyAsync(string? keyId, CancellationToken cancellationToken) =>
			throw new NotSupportedException();
	}
}
