using Org.BouncyCastle.Crypto.Parameters;

namespace Utilities.Jwt.Ed25519.Interfaces;

/// <summary>
/// Builds JWTs signed with an Ed25519 private key.
/// </summary>
public interface IJwtSigner
{
	/// <summary>
	/// Builds a signed JWT from the payload.
	/// </summary>
	/// <typeparam name="T">The payload type.</typeparam>
	/// <param name="payload">The payload to sign.</param>
	/// <param name="privateKey">The Ed25519 private key that signs the token.</param>
	/// <returns>The signed JWT.</returns>
	public string BuildToken<T>(T payload, Ed25519PrivateKeyParameters privateKey)
		where T : IBaseJwtPayload;
}
