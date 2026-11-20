using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Options;

namespace Utilities.Jwt.Ed25519.Services;

/// <summary>
/// Gives one fixed private key from <see cref="StaticSigningKeyOptions"/>.
/// </summary>
/// <param name="options">The options with the PEM private key and the key ID.</param>
internal sealed class StaticSigningKeyResolver(IOptions<StaticSigningKeyOptions> options) : IJwtSigningKeyResolver
{
	// Load the key once. The key does not change, so the resolver is safe as a Singleton.
	private readonly JwtSigningKey _key = new(options.Value.KeyId, Ed25519KeyLoader.LoadPrivateKey(options.Value.PrivateKeyPem));

	/// <inheritdoc />
	/// <exception cref="InvalidOperationException">Thrown when <paramref name="keyId"/> is not the key ID of the fixed key.</exception>
	public ValueTask<JwtSigningKey> ResolveSigningKeyAsync(string? keyId, CancellationToken cancellationToken)
	{
		if (keyId != null && keyId != _key.KeyId)
			throw new InvalidOperationException("The fixed signing key does not have the requested key ID.");

		return new ValueTask<JwtSigningKey>(_key);
	}
}
