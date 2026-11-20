using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Options;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Extensions;

/// <summary>
/// Registers the JWT services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class ServiceCollectionExtensions
{
	/// <summary>
	/// Registers <see cref="IJwtSigner"/>, <see cref="IJwtValidator"/>, and <see cref="JwtValidationOptions"/>.
	/// </summary>
	/// <param name="services">The service collection.</param>
	/// <returns>A builder that adds the signing and validation keys.</returns>
	/// <remarks>
	/// Call <see cref="JwtEd25519Builder.AddSigning(Action{StaticSigningKeyOptions})"/> or
	/// <see cref="JwtEd25519Builder.AddValidation(Action{StaticValidationKeyOptions})"/> to add a key source.
	/// </remarks>
	public static JwtEd25519Builder AddJwtEd25519(this IServiceCollection services)
	{
		_ = services.AddOptions<JwtValidationOptions>()
			.ValidateDataAnnotations()
			.ValidateOnStart();

		services.TryAddSingleton(TimeProvider.System);

		// The signer and the validator have no state. Their lifetime follows the Scoped default of custom resolvers.
		services.TryAddScoped<IJwtSigner>(sp => new JwtSigner(sp.GetService<IJwtSigningKeyResolver>()));
		services.TryAddScoped<IJwtValidator>(sp => new JwtValidator(
			sp.GetService<IJwtKeyResolver>(),
			sp.GetRequiredService<IOptions<JwtValidationOptions>>(),
			sp.GetRequiredService<TimeProvider>()));

		return new JwtEd25519Builder(services);
	}
}
