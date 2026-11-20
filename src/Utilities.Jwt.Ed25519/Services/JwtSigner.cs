using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Services;

/// <summary>
/// Builds JWTs signed with an Ed25519 private key.
/// </summary>
public sealed class JwtSigner : IJwtSigner
{
	private static readonly JsonSerializerOptions _serializerOptions = new()
	{
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
	};

	/// <inheritdoc />
	public string BuildToken<T>(T payload, Ed25519PrivateKeyParameters privateKey)
		where T : IBaseJwtPayload
	{
		var encodedHeader = Base64Url.Encode(Encoding.UTF8.GetBytes(JwtHeader.Export()));
		var encodedPayload = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(payload, _serializerOptions));
		var signedData = $"{encodedHeader}.{encodedPayload}";

		return $"{signedData}.{Base64Url.Encode(Sign(signedData, privateKey))}";
	}

	/// <summary>
	/// Signs the data with the Ed25519 private key.
	/// </summary>
	/// <param name="signedData">The encoded header and payload, joined with a dot.</param>
	/// <param name="privateKey">The Ed25519 private key.</param>
	/// <returns>The signature bytes.</returns>
	private static byte[] Sign(string signedData, Ed25519PrivateKeyParameters privateKey)
	{
		var bytes = Encoding.ASCII.GetBytes(signedData);
		var signer = new Ed25519Signer();
		signer.Init(true, privateKey);
		signer.BlockUpdate(bytes, 0, bytes.Length);

		return signer.GenerateSignature();
	}
}
