using System.Threading;
using System.Threading.Tasks;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Interfaces;

/// <summary>
/// Gives the public key that verifies a token.
/// </summary>
/// <remarks>
/// The package has a built-in resolver for one fixed key. Write a custom resolver for other cases,
/// for example one public key for each member.
/// </remarks>
public interface IJwtKeyResolver
{
	/// <summary>
	/// Gets the public key for the token.
	/// </summary>
	/// <param name="context">The <c>kid</c> header and the unverified <c>iss</c> and <c>sub</c> claims.</param>
	/// <param name="cancellationToken">The token that cancels the operation.</param>
	/// <returns>
	/// The public key, or <see langword="null"/> when no key matches. A <see langword="null"/> result rejects the token.
	/// Do not return a fallback key.
	/// </returns>
	public ValueTask<JwtVerificationKey?> ResolvePublicKeyAsync(JwtKeyResolutionContext context, CancellationToken cancellationToken);
}
