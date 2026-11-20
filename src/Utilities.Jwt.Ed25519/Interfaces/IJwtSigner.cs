using System;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;

namespace Utilities.Jwt.Ed25519.Interfaces;

/// <summary>
/// Builds JWTs signed with an Ed25519 private key.
/// </summary>
public interface IJwtSigner
{
	/// <summary>
	/// Builds a signed JWT from the payload with the given key.
	/// </summary>
	/// <typeparam name="T">The payload type.</typeparam>
	/// <param name="payload">The payload to sign.</param>
	/// <param name="privateKey">The Ed25519 private key that signs the token.</param>
	/// <param name="keyId">The value of the <c>kid</c> header, or <see langword="null"/> for no <c>kid</c>.</param>
	/// <returns>The signed JWT.</returns>
	/// <exception cref="ArgumentException">Thrown when <paramref name="keyId"/> does not have the key ID format.</exception>
	public string BuildToken<T>(T payload, Ed25519PrivateKeyParameters privateKey, string? keyId = null)
		where T : IBaseJwtPayload;

	/// <summary>
	/// Builds a signed JWT from the payload with the key from <see cref="IJwtSigningKeyResolver"/>.
	/// </summary>
	/// <typeparam name="T">The payload type.</typeparam>
	/// <param name="payload">The payload to sign.</param>
	/// <param name="keyId">The requested key ID, or <see langword="null"/> for the current key.</param>
	/// <param name="cancellationToken">The token that cancels the operation.</param>
	/// <returns>The signed JWT. The <c>kid</c> header is the key ID of the resolved key.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the signer has no <see cref="IJwtSigningKeyResolver"/>.</exception>
	public ValueTask<string> BuildTokenAsync<T>(T payload, string? keyId, CancellationToken cancellationToken)
		where T : IBaseJwtPayload;
}
