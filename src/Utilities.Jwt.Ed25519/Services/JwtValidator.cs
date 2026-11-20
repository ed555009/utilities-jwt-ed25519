using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Services;

/// <summary>
/// Validates JWTs signed with an Ed25519 private key.
/// </summary>
public sealed class JwtValidator : IJwtValidator
{
	/// <inheritdoc />
	public bool TryValidateToken<T>(string token, Ed25519PublicKeyParameters publicKey, [NotNullWhen(true)] out T? payload)
		where T : IBaseJwtPayload
	{
		payload = default;

		if (!TokenParts.TryParse(token, out var parts))
			return false;

		// Verify the signature first. Do not parse untrusted JSON before this check.
		if (!VerifySignature(parts, publicKey))
			return false;

		try
		{
			if (!IsValidHeader(parts.Header) || !IsWithinLifetime(parts.Payload, DateTimeOffset.UtcNow))
				return false;

			var result = JsonSerializer.Deserialize<T>(parts.Payload);

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
	/// Verifies the token signature with the Ed25519 public key.
	/// </summary>
	/// <param name="parts">The decoded token parts.</param>
	/// <param name="publicKey">The Ed25519 public key.</param>
	/// <returns>True if the signature is valid; otherwise, false.</returns>
	private static bool VerifySignature(TokenParts parts, Ed25519PublicKeyParameters publicKey)
	{
		var bytes = Encoding.ASCII.GetBytes(parts.SignedData);
		var verifier = new Ed25519Signer();
		verifier.Init(false, publicKey);
		verifier.BlockUpdate(bytes, 0, bytes.Length);

		return verifier.VerifySignature(parts.Signature);
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
}
