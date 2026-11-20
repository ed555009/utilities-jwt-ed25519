using System.Threading;
using System.Threading.Tasks;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Interfaces;

/// <summary>
/// Gives the private key that signs a token.
/// </summary>
/// <remarks>
/// The package has a built-in resolver for one fixed key. Write a custom resolver for other cases,
/// for example one private key for each tenant.
/// </remarks>
public interface IJwtSigningKeyResolver
{
	/// <summary>
	/// Gets the signing key for the key ID.
	/// </summary>
	/// <param name="keyId">The requested key ID, or <see langword="null"/> for the current key.</param>
	/// <param name="cancellationToken">The token that cancels the operation.</param>
	/// <returns>The signing key. The signer writes its <see cref="JwtSigningKey.KeyId"/> to the <c>kid</c> header.</returns>
	public ValueTask<JwtSigningKey> ResolveSigningKeyAsync(string? keyId, CancellationToken cancellationToken);
}
