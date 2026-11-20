using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Options;

namespace Utilities.Jwt.Ed25519.Services;

/// <summary>
/// Gives one fixed public key from <see cref="StaticValidationKeyOptions"/>.
/// </summary>
/// <param name="options">The options with the PEM public key and the key ID.</param>
internal sealed class StaticKeyResolver(IOptions<StaticValidationKeyOptions> options) : IJwtKeyResolver
{
	private readonly string? _keyId = options.Value.KeyId;

	// Load the key once. The key does not change, so the resolver is safe as a Singleton.
	private readonly JwtVerificationKey _key = new(Ed25519KeyLoader.LoadPublicKey(options.Value.PublicKeyPem));

	/// <inheritdoc />
	public ValueTask<JwtVerificationKey?> ResolvePublicKeyAsync(JwtKeyResolutionContext context, CancellationToken cancellationToken)
	{
		// Without a configured key ID, the signature check alone decides. With a key ID, the kid must match.
		var key = _keyId == null || context.KeyId == _keyId ? _key : null;

		return new ValueTask<JwtVerificationKey?>(key);
	}
}
