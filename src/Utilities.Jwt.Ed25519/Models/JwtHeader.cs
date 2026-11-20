using System.IO;
using System.Text;
using System.Text.Json;

namespace Utilities.Jwt.Ed25519.Models;

/// <summary>
/// The JOSE header of a JWT that this package builds.
/// </summary>
/// <param name="keyId">The value of the <c>kid</c> header, or <see langword="null"/> for a token without <c>kid</c>.</param>
public sealed class JwtHeader(string? keyId = null)
{
	/// <summary>
	/// The algorithm of every token that this package builds and accepts.
	/// </summary>
	public const string EdDsaAlgorithm = "EdDSA";

	/// <summary>
	/// The token type of every token that this package builds and accepts.
	/// </summary>
	public const string JwtType = "JWT";

	/// <summary>
	/// Gets the value of the <c>alg</c> header, which is EdDSA.
	/// </summary>
	public string Algorithm => EdDsaAlgorithm;

	/// <summary>
	/// Gets the value of the <c>typ</c> header, which is JWT.
	/// </summary>
	public string Type => JwtType;

	/// <summary>
	/// Gets the value of the <c>kid</c> header, or <see langword="null"/> when the token has no <c>kid</c>.
	/// </summary>
	public string? KeyId { get; } = keyId;

	/// <summary>
	/// Exports the header as a JSON string.
	/// </summary>
	/// <returns>The header JSON. The <c>kid</c> property is present only when <see cref="KeyId"/> is not null.</returns>
	public string Export()
	{
		using var stream = new MemoryStream();

		using (var writer = new Utf8JsonWriter(stream))
		{
			// Keep the order alg, typ. A token without kid then stays the same as in version 8.x.
			writer.WriteStartObject();
			writer.WriteString("alg", Algorithm);
			writer.WriteString("typ", Type);

			if (KeyId != null)
				writer.WriteString("kid", KeyId);

			writer.WriteEndObject();
		}

		return Encoding.UTF8.GetString(stream.ToArray());
	}
}
