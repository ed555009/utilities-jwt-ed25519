using System;

namespace Utilities.Jwt.Ed25519.Services;

/// <summary>
/// Encodes and decodes Base64 URL strings without padding (RFC 7515 section 2).
/// </summary>
internal static class Base64Url
{
	/// <summary>
	/// Encodes bytes to a Base64 URL string without padding.
	/// </summary>
	/// <param name="data">The bytes to encode.</param>
	/// <returns>The Base64 URL string.</returns>
	public static string Encode(byte[] data) =>
		Convert.ToBase64String(data)
			.Replace('+', '-')
			.Replace('/', '_')
			.TrimEnd('=');

	/// <summary>
	/// Decodes a Base64 URL string without padding.
	/// </summary>
	/// <param name="data">The Base64 URL string to decode.</param>
	/// <param name="bytes">The decoded bytes.</param>
	/// <returns>True if the string is valid Base64 URL; otherwise, false.</returns>
	public static bool TryDecode(string data, out byte[] bytes)
	{
		bytes = Array.Empty<byte>();

		// Accept only the Base64 URL alphabet. Reject padding and whitespace.
		// The check also keeps the signed data ASCII.
		foreach (var c in data)
		{
			if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'))
				return false;
		}

		var base64 = data
			.Replace('-', '+')
			.Replace('_', '/')
			.PadRight(data.Length + (4 - data.Length % 4) % 4, '=');
		var buffer = new byte[base64.Length / 4 * 3];

		if (!Convert.TryFromBase64String(base64, buffer, out var written))
			return false;

		bytes = buffer.AsSpan(0, written).ToArray();
		return true;
	}
}
