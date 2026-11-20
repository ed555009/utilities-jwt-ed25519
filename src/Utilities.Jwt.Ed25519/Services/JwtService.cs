using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Services
{
	public class JwtService : IJwtService
	{
		/// <summary>
		/// Builds a JWT token from the given payload and private key parameters.
		/// </summary>
		/// <typeparam name="T">The type of the JWT payload, which must implement IBaseJwtPayload.</typeparam>
		/// <param name="jwtPayload">The JWT payload to include in the token.</param>
		/// <param name="privateKeyParameters">The Ed25519 private key parameters used to sign the token.</param>
		/// <returns>A JWT token as a string.</returns>
		public static string BuildToken<T>(T jwtPayload, Ed25519PrivateKeyParameters privateKeyParameters)
			where T : IBaseJwtPayload
		{
			var payload = Base64UrlEncode(Encoding.UTF8.GetBytes(
				JsonSerializer.Serialize(jwtPayload, new JsonSerializerOptions
				{
					DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
				})));
			var data = $"{GetEncodedHeader()}.{payload}";
			var signature = GetEncodedSignature(data, privateKeyParameters);

			return $"{data}.{signature}";
		}

		/// <summary>
		/// Validates a JWT token using the provided Ed25519 public key parameters.
		/// </summary>
		/// <typeparam name="T">The type of the JWT payload, which must implement <see cref="IBaseJwtPayload"/>.</typeparam>
		/// <param name="token">The JWT token to validate.</param>
		/// <param name="publicKeyParameters">The Ed25519 public key parameters used to verify the token's signature.</param>
		/// <param name="payload">The deserialized JWT payload if the token is valid; otherwise, the default value of <typeparamref name="T"/>.</param>
		/// <returns>True if the token is valid; otherwise, false.</returns>
		/// <remarks>
		/// The method returns false and does not throw when the token is malformed.
		/// The method returns false when the current time is at or after <c>exp</c>, or before <c>nbf</c>.
		/// The method does not check the other claims.
		/// </remarks>
		public static bool ValidateToken<T>(string token, Ed25519PublicKeyParameters publicKeyParameters, out T payload)
			where T : IBaseJwtPayload
		{
			payload = default!;

			if (!TryDecodeToken(token, out var signedData, out var headerBytes, out var payloadBytes, out var signature))
				return false;

			// Verify the signature first. Do not parse untrusted JSON before this check.
			if (!VerifySignature(signedData, signature, publicKeyParameters))
				return false;

			try
			{
				if (!IsValidHeader(headerBytes) || !IsWithinLifetime(payloadBytes, DateTimeOffset.UtcNow))
					return false;

				var result = JsonSerializer.Deserialize<T>(payloadBytes);

				if (result == null)
					return false;

				// Set the payload only after all checks pass. A false result never carries claims.
				payload = result;
				return true;
			}
			catch (JsonException)
			{
				return false;
			}
		}

		/// <summary>
		/// Loads an Ed25519 private key from a given string or file path.
		/// </summary>
		/// <param name="dataOrPath">The string containing the key data or the file path to the key.</param>
		/// <param name="loadKeyType">Specifies whether the key is provided as a string or a file path. Default is <see cref="LoadKeyType.String"/>.</param>
		/// <returns>An instance of <see cref="Ed25519PrivateKeyParameters"/> representing the loaded private key.</returns>
		/// <exception cref="InvalidDataException">Thrown when the provided key data is not a valid Ed25519 private key format.</exception>
		public static Ed25519PrivateKeyParameters LoadPrivateKey(
			string dataOrPath,
			LoadKeyType loadKeyType = LoadKeyType.String)
		{
			var pemObject = loadKeyType == LoadKeyType.String ? FromString(dataOrPath) : FromFile(dataOrPath);

			if (pemObject is Ed25519PrivateKeyParameters privateKeyParameters)
				return privateKeyParameters;

			throw new InvalidDataException("Invalid Ed25519 private key format");
		}

		/// <summary>
		/// Loads an Ed25519 public key from a given string or file path.
		/// </summary>
		/// <param name="dataOrPath">The public key data as a string or the file path to the public key.</param>
		/// <param name="loadKeyType">Specifies whether the input is a string or a file path. Default is <see cref="LoadKeyType.String"/>.</param>
		/// <returns>An instance of <see cref="Ed25519PublicKeyParameters"/> representing the loaded public key.</returns>
		/// <exception cref="InvalidDataException">Thrown when the provided data does not represent a valid Ed25519 public key.</exception>
		public static Ed25519PublicKeyParameters LoadPublicKey(
			string dataOrPath,
			LoadKeyType loadKeyType = LoadKeyType.String)
		{
			var pemObject = loadKeyType == LoadKeyType.String ? FromString(dataOrPath) : FromFile(dataOrPath);

			if (pemObject is Ed25519PublicKeyParameters publicKeyParameters)
				return publicKeyParameters;

			throw new InvalidDataException("Invalid Ed25519 public key format");
		}

		/// <summary>
		/// Splits a JWT token and decodes its header, payload, and signature.
		/// </summary>
		/// <param name="token">The JWT token to decode.</param>
		/// <param name="signedData">The encoded header and payload, joined with a dot.</param>
		/// <param name="header">The decoded header bytes.</param>
		/// <param name="payload">The decoded payload bytes.</param>
		/// <param name="signature">The decoded signature bytes.</param>
		/// <returns>True if the token has 3 Base64 URL encoded parts; otherwise, false.</returns>
		private static bool TryDecodeToken(
			string token,
			out string signedData,
			out byte[] header,
			out byte[] payload,
			out byte[] signature)
		{
			signedData = string.Empty;
			header = payload = signature = Array.Empty<byte>();

			if (string.IsNullOrEmpty(token))
				return false;

			var parts = token.Split('.');

			if (parts.Length != 3
				|| !TryBase64UrlDecode(parts[0], out header)
				|| !TryBase64UrlDecode(parts[1], out payload)
				|| !TryBase64UrlDecode(parts[2], out signature))
				return false;

			signedData = $"{parts[0]}.{parts[1]}";
			return true;
		}

		/// <summary>
		/// Decodes a Base64 URL encoded string without padding.
		/// </summary>
		/// <param name="data">The Base64 URL encoded string to decode.</param>
		/// <param name="bytes">The decoded bytes.</param>
		/// <returns>True if the string is valid Base64 URL; otherwise, false.</returns>
		private static bool TryBase64UrlDecode(string data, out byte[] bytes)
		{
			bytes = Array.Empty<byte>();

			// Accept only the Base64 URL alphabet (RFC 7515 section 2).
			// The check also keeps the signed data ASCII. VerifySignature uses the character count as the byte count.
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

		/// <summary>
		/// Checks that the JWT header is a JSON object with the expected algorithm and type.
		/// </summary>
		/// <param name="header">The decoded header bytes.</param>
		/// <returns>True if <c>alg</c> is EdDSA and <c>typ</c> is JWT; otherwise, false.</returns>
		/// <exception cref="JsonException">Thrown when the header is not valid JSON.</exception>
		private static bool IsValidHeader(byte[] header)
		{
			using var document = JsonDocument.Parse(header);
			var root = document.RootElement;

			return root.ValueKind == JsonValueKind.Object
				&& HasStringValue(root, "alg", JwtHeader.Algorithm)
				&& HasStringValue(root, "typ", JwtHeader.Type);
		}

		/// <summary>
		/// Checks the <c>exp</c> and <c>nbf</c> claims against the current time.
		/// </summary>
		/// <param name="payload">The decoded payload bytes.</param>
		/// <param name="now">The current time.</param>
		/// <returns>True if the token is in its lifetime; otherwise, false.</returns>
		/// <exception cref="JsonException">Thrown when the payload is not valid JSON.</exception>
		private static bool IsWithinLifetime(byte[] payload, DateTimeOffset now)
		{
			using var document = JsonDocument.Parse(payload);
			var root = document.RootElement;

			if (root.ValueKind != JsonValueKind.Object)
				return false;

			// Use milliseconds. NumericDate values can have a fraction (RFC 7519 section 2).
			var seconds = now.ToUnixTimeMilliseconds() / 1000d;

			// RFC 7519 makes exp and nbf optional. Check each claim only when the token has it.
			if (root.TryGetProperty("exp", out var exp)
				&& (!TryGetNumericDate(exp, out var expiration) || seconds >= expiration))
				return false;

			if (root.TryGetProperty("nbf", out var nbf)
				&& (!TryGetNumericDate(nbf, out var notBefore) || seconds < notBefore))
				return false;

			return true;
		}

		/// <summary>
		/// Reads a JSON number as a NumericDate value.
		/// </summary>
		/// <param name="element">The JSON element to read.</param>
		/// <param name="value">The number of seconds since the Unix epoch.</param>
		/// <returns>True if the element is a JSON number; otherwise, false.</returns>
		private static bool TryGetNumericDate(JsonElement element, out double value)
		{
			value = 0;
			return element.ValueKind == JsonValueKind.Number && element.TryGetDouble(out value);
		}

		/// <summary>
		/// Checks that a JSON object has a string property with the expected value.
		/// </summary>
		/// <param name="element">The JSON object.</param>
		/// <param name="name">The property name.</param>
		/// <param name="expected">The expected string value.</param>
		/// <returns>True if the property is a string with the expected value; otherwise, false.</returns>
		private static bool HasStringValue(JsonElement element, string name, string expected) =>
			element.TryGetProperty(name, out var value)
			&& value.ValueKind == JsonValueKind.String
			&& value.GetString() == expected;

		/// <summary>
		/// Encodes the JWT header to a Base64 URL encoded string.
		/// </summary>
		/// <returns>A Base64 URL encoded string representing the JWT header.</returns>
		static string GetEncodedHeader() =>
			Base64UrlEncode(Encoding.UTF8.GetBytes(JwtHeader.Export()));

		/// <summary>
		/// Generates and encodes the JWT signature to a Base64 URL encoded string.
		/// </summary>
		/// <param name="data">The data to be signed.</param>
		/// <param name="privateKeyParameters">The Ed25519 private key parameters used to sign the data.</param>
		/// <returns>A Base64 URL encoded string representing the JWT signature.</returns>
		static string GetEncodedSignature(string data, Ed25519PrivateKeyParameters privateKeyParameters)
		{
			var signer = new Ed25519Signer();
			signer.Init(true, privateKeyParameters);
			signer.BlockUpdate(Encoding.UTF8.GetBytes(data), 0, data.Length);

			return Base64UrlEncode(signer.GenerateSignature());
		}

		/// <summary>
		/// Verifies the JWT signature using the provided Ed25519 public key parameters.
		/// </summary>
		/// <param name="data">The data to be verified.</param>
		/// <param name="signature">The signature to verify.</param>
		/// <param name="publicKeyParameters">The Ed25519 public key parameters used to verify the signature.</param>
		/// <returns>True if the signature is valid; otherwise, false.</returns>
		static bool VerifySignature(string data, byte[] signature, Ed25519PublicKeyParameters publicKeyParameters)
		{
			var verifier = new Ed25519Signer();
			verifier.Init(false, publicKeyParameters);
			verifier.BlockUpdate(Encoding.UTF8.GetBytes(data), 0, data.Length);

			return verifier.VerifySignature(signature);
		}

		/// <summary>
		/// Reads a PEM encoded object from a string.
		/// </summary>
		/// <param name="data">The string containing the PEM encoded data.</param>
		/// <returns>The object read from the PEM encoded string.</returns>
		static object FromString(string data)
		{
			using var stringReader = new StringReader(data);
			return new PemReader(stringReader).ReadObject();
		}

		/// <summary>
		/// Reads an object from a PEM file at the specified path.
		/// </summary>
		/// <param name="path">The file path to the PEM file.</param>
		/// <returns>The object read from the PEM file.</returns>
		static object FromFile(string path)
		{
			using var fileReader = File.OpenText(path);
			return new PemReader(fileReader).ReadObject();
		}

		/// <summary>
		/// Encodes the specified byte array to a Base64 URL encoded string.
		/// </summary>
		/// <param name="data">The byte array to encode.</param>
		/// <returns>A Base64 URL encoded string representation of the input byte array.</returns>
		static string Base64UrlEncode(byte[] data) =>
			Convert.ToBase64String(data)
				.Replace('+', '-')
				.Replace('/', '_')
				.Replace("=", "");

		/// <summary>
		/// Decodes a Base64 URL encoded string to a byte array.
		/// </summary>
		/// <param name="data">The Base64 URL encoded string to decode.</param>
		/// <returns>A byte array representing the decoded data.</returns>
		/// <remarks>
		/// This method replaces URL-safe characters ('-' and '_') with Base64 characters ('+' and '/')
		/// and pads the string with '=' characters to ensure it has a length that is a multiple of 4.
		/// </remarks>
		public static byte[] Base64UrlDecode(string data) =>
			Convert.FromBase64String(data
				.Replace('-', '+')
				.Replace('_', '/')
				.PadRight(data.Length + (4 - data.Length % 4) % 4, '='));
	}
}
