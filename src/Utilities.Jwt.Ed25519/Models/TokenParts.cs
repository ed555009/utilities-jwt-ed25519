using System.Diagnostics.CodeAnalysis;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Models;

/// <summary>
/// Holds the decoded parts of a JWT.
/// </summary>
/// <param name="signedData">The encoded header and payload, joined with a dot.</param>
/// <param name="header">The decoded header bytes.</param>
/// <param name="payload">The decoded payload bytes.</param>
/// <param name="signature">The decoded signature bytes.</param>
internal sealed class TokenParts(string signedData, byte[] header, byte[] payload, byte[] signature)
{
	/// <summary>
	/// Gets the encoded header and payload, joined with a dot.
	/// </summary>
	public string SignedData { get; } = signedData;

	/// <summary>
	/// Gets the decoded header bytes.
	/// </summary>
	public byte[] Header { get; } = header;

	/// <summary>
	/// Gets the decoded payload bytes.
	/// </summary>
	public byte[] Payload { get; } = payload;

	/// <summary>
	/// Gets the decoded signature bytes.
	/// </summary>
	public byte[] Signature { get; } = signature;

	/// <summary>
	/// Splits a JWT and decodes its header, payload, and signature.
	/// </summary>
	/// <param name="token">The JWT to decode.</param>
	/// <param name="parts">The decoded parts when the token is valid; otherwise, <see langword="null"/>.</param>
	/// <returns>True if the token has 3 Base64 URL parts; otherwise, false.</returns>
	public static bool TryParse(string? token, [NotNullWhen(true)] out TokenParts? parts)
	{
		parts = null;

		if (string.IsNullOrEmpty(token))
			return false;

		var segments = token.Split('.');

		if (segments.Length != 3
			|| !Base64Url.TryDecode(segments[0], out var header)
			|| !Base64Url.TryDecode(segments[1], out var payload)
			|| !Base64Url.TryDecode(segments[2], out var signature))
			return false;

		parts = new TokenParts($"{segments[0]}.{segments[1]}", header, payload, signature);
		return true;
	}
}
