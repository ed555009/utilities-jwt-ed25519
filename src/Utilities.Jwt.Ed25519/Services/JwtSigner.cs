using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Services;

/// <summary>
/// Builds JWTs signed with an Ed25519 private key.
/// </summary>
/// <param name="signingKeyResolver">
/// The resolver for <see cref="BuildTokenAsync{T}"/>, or <see langword="null"/> when only <see cref="BuildToken{T}"/> is in use.
/// </param>
public sealed class JwtSigner(IJwtSigningKeyResolver? signingKeyResolver) : IJwtSigner
{
	private static readonly JsonSerializerOptions _serializerOptions = new()
	{
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
	};

	private readonly IJwtSigningKeyResolver? _signingKeyResolver = signingKeyResolver;

	/// <summary>
	/// Creates a signer without a resolver. Use <see cref="BuildToken{T}"/> with this signer.
	/// </summary>
	public JwtSigner()
		: this(null)
	{
	}

	/// <inheritdoc />
	public string BuildToken<T>(T payload, Ed25519PrivateKeyParameters privateKey, string? keyId = null)
		where T : IBaseJwtPayload
	{
		if (keyId != null && !KeyIdFormat.IsValid(keyId))
			throw new ArgumentException($"The key ID must be 1 to {KeyIdFormat.MaxLength} characters from [A-Za-z0-9._:-].", nameof(keyId));

		var encodedHeader = Base64Url.Encode(Encoding.UTF8.GetBytes(new JwtHeader(keyId).Export()));
		var encodedPayload = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(payload, _serializerOptions));
		var signedData = $"{encodedHeader}.{encodedPayload}";

		return $"{signedData}.{Base64Url.Encode(Sign(signedData, privateKey))}";
	}

	/// <inheritdoc />
	public async ValueTask<string> BuildTokenAsync<T>(T payload, string? keyId, CancellationToken cancellationToken)
		where T : IBaseJwtPayload
	{
		if (_signingKeyResolver == null)
			throw new InvalidOperationException("BuildTokenAsync needs an IJwtSigningKeyResolver. Register one with AddJwtEd25519().AddSigning().");

		var key = await _signingKeyResolver.ResolveSigningKeyAsync(keyId, cancellationToken).ConfigureAwait(false);

		// Write the key ID of the resolved key, not the requested key ID. The kid then always matches the signing key.
		return BuildToken(payload, key.PrivateKey, key.KeyId);
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
