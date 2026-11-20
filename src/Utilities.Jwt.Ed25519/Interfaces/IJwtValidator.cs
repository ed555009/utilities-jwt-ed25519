using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Interfaces;

/// <summary>
/// Validates JWTs signed with an Ed25519 private key.
/// </summary>
public interface IJwtValidator
{
	/// <summary>
	/// Validates the token with the given public key and reads its payload.
	/// </summary>
	/// <typeparam name="T">The payload type.</typeparam>
	/// <param name="token">The JWT to validate.</param>
	/// <param name="publicKey">The Ed25519 public key that verifies the signature.</param>
	/// <param name="payload">The payload when the token is valid; otherwise, <see langword="null"/>.</param>
	/// <returns>True if the token is valid; otherwise, false.</returns>
	/// <remarks>
	/// The method returns false and does not throw when the token is malformed.
	/// The method returns false when the current time is at or after <c>exp</c>, or before <c>nbf</c>.
	/// The method does not check the other claims.
	/// </remarks>
	public bool TryValidateToken<T>(string token, Ed25519PublicKeyParameters publicKey, [NotNullWhen(true)] out T? payload)
		where T : IBaseJwtPayload;

	/// <summary>
	/// Validates the token with the key from <see cref="IJwtKeyResolver"/> and reads its payload.
	/// </summary>
	/// <typeparam name="T">The payload type.</typeparam>
	/// <param name="token">The JWT to validate.</param>
	/// <param name="cancellationToken">The token that cancels the operation.</param>
	/// <returns>The validation result. A failed result has the reason in <see cref="JwtValidationResult{T}.Error"/>.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the validator has no <see cref="IJwtKeyResolver"/>.</exception>
	public ValueTask<JwtValidationResult<T>> ValidateTokenAsync<T>(string token, CancellationToken cancellationToken)
		where T : IBaseJwtPayload;
}
