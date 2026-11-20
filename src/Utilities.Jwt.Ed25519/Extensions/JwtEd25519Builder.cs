using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Options;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Extensions;

/// <summary>
/// Adds the signing and validation key sources after <see cref="ServiceCollectionExtensions.AddJwtEd25519"/>.
/// </summary>
/// <param name="services">The service collection.</param>
public sealed class JwtEd25519Builder(IServiceCollection services)
{
	/// <summary>
	/// Gets the service collection.
	/// </summary>
	public IServiceCollection Services { get; } = services;

	/// <summary>
	/// Signs tokens with one fixed private key from <see cref="StaticSigningKeyOptions"/>.
	/// </summary>
	/// <param name="configure">Sets the PEM private key and the key ID.</param>
	/// <returns>The builder.</returns>
	/// <remarks>The host validates the key at startup and stops when the key is not an Ed25519 private key.</remarks>
	public JwtEd25519Builder AddSigning(Action<StaticSigningKeyOptions> configure)
	{
		_ = Services.AddOptions<StaticSigningKeyOptions>()
			.Configure(configure)
			.ValidateDataAnnotations()
			.ValidateOnStart();

		Services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<StaticSigningKeyOptions>, StaticKeyOptionsValidator>());
		_ = Services.Replace(ServiceDescriptor.Singleton<IJwtSigningKeyResolver, StaticSigningKeyResolver>());

		return this;
	}

	/// <summary>
	/// Signs tokens with keys from a custom resolver. The resolver is Scoped.
	/// </summary>
	/// <typeparam name="TResolver">The resolver type.</typeparam>
	/// <returns>The builder.</returns>
	public JwtEd25519Builder AddSigning<TResolver>()
		where TResolver : class, IJwtSigningKeyResolver
	{
		_ = Services.Replace(ServiceDescriptor.Scoped<IJwtSigningKeyResolver, TResolver>());

		return this;
	}

	/// <summary>
	/// Validates tokens with one fixed public key from <see cref="StaticValidationKeyOptions"/>.
	/// </summary>
	/// <param name="configure">Sets the PEM public key and the key ID.</param>
	/// <returns>The builder.</returns>
	/// <remarks>The host validates the key at startup and stops when the key is not an Ed25519 public key.</remarks>
	public JwtEd25519Builder AddValidation(Action<StaticValidationKeyOptions> configure)
	{
		_ = Services.AddOptions<StaticValidationKeyOptions>()
			.Configure(configure)
			.ValidateDataAnnotations()
			.ValidateOnStart();

		Services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<StaticValidationKeyOptions>, StaticKeyOptionsValidator>());
		_ = Services.Replace(ServiceDescriptor.Singleton<IJwtKeyResolver, StaticKeyResolver>());

		return this;
	}

	/// <summary>
	/// Validates tokens with keys from a custom resolver. The resolver is Scoped.
	/// </summary>
	/// <typeparam name="TResolver">The resolver type.</typeparam>
	/// <returns>The builder.</returns>
	/// <remarks>A Scoped resolver can use a Scoped <c>DbContext</c>.</remarks>
	public JwtEd25519Builder AddValidation<TResolver>()
		where TResolver : class, IJwtKeyResolver
	{
		_ = Services.Replace(ServiceDescriptor.Scoped<IJwtKeyResolver, TResolver>());

		return this;
	}

	/// <summary>
	/// Sets the validation options.
	/// </summary>
	/// <param name="configure">Sets the clock skew and the expiration rule.</param>
	/// <returns>The builder.</returns>
	public JwtEd25519Builder ConfigureValidation(Action<JwtValidationOptions> configure)
	{
		_ = Services.Configure(configure);

		return this;
	}
}
