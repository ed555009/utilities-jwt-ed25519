using System;
using System.Text.Json;
using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Options;

namespace Utilities.Jwt.Ed25519.Services;

/// <summary>
/// Reads and checks the JSON header and the JSON payload of a token.
/// </summary>
/// <remarks>
/// Each method returns a result for malformed JSON. No method throws <see cref="JsonException"/>.
/// The methods never read the <c>jwk</c>, <c>jku</c>, <c>x5u</c> or <c>x5c</c> headers. A token cannot give its own key.
/// </remarks>
internal static class JwtContentReader
{
	/// <summary>
	/// Checks the header and reads the <c>kid</c> header.
	/// </summary>
	/// <param name="header">The decoded header bytes.</param>
	/// <param name="keyId">The <c>kid</c> header, or <see langword="null"/> when the header has no <c>kid</c>.</param>
	/// <returns><see cref="JwtValidationError.None"/>, <see cref="JwtValidationError.InvalidHeader"/>, or <see cref="JwtValidationError.InvalidKeyId"/>.</returns>
	public static JwtValidationError ReadHeader(byte[] header, out string? keyId)
	{
		keyId = null;

		try
		{
			using var document = JsonDocument.Parse(header);
			var root = document.RootElement;

			// The package supports no critical header extensions (RFC 7515 section 4.1.11).
			if (root.ValueKind != JsonValueKind.Object
				|| !HasStringValue(root, "alg", JwtHeader.EdDsaAlgorithm)
				|| !HasStringValue(root, "typ", JwtHeader.JwtType)
				|| root.TryGetProperty("crit", out _))
				return JwtValidationError.InvalidHeader;

			if (!root.TryGetProperty("kid", out var kid))
				return JwtValidationError.None;

			// Validate the format before a resolver gets the value.
			if (kid.ValueKind != JsonValueKind.String || !KeyIdFormat.IsValid(kid.GetString()))
				return JwtValidationError.InvalidKeyId;

			keyId = kid.GetString();
			return JwtValidationError.None;
		}
		catch (JsonException)
		{
			return JwtValidationError.InvalidHeader;
		}
	}

	/// <summary>
	/// Reads the <c>iss</c> and <c>sub</c> claims before signature verification.
	/// </summary>
	/// <param name="payload">The decoded payload bytes.</param>
	/// <param name="issuer">The <c>iss</c> claim when it is a string; otherwise, <see langword="null"/>.</param>
	/// <param name="subject">The <c>sub</c> claim when it is a string; otherwise, <see langword="null"/>.</param>
	/// <returns>True if the payload is a JSON object; otherwise, false.</returns>
	public static bool TryReadUnverifiedClaims(byte[] payload, out string? issuer, out string? subject)
	{
		issuer = subject = null;

		try
		{
			using var document = JsonDocument.Parse(payload);
			var root = document.RootElement;

			if (root.ValueKind != JsonValueKind.Object)
				return false;

			issuer = GetOptionalString(root, "iss");
			subject = GetOptionalString(root, "sub");
			return true;
		}
		catch (JsonException)
		{
			return false;
		}
	}

	/// <summary>
	/// Checks the lifetime claims and the subject binding of a verified payload.
	/// </summary>
	/// <param name="payload">The decoded payload bytes.</param>
	/// <param name="now">The current time.</param>
	/// <param name="options">The validation options.</param>
	/// <param name="expectedSubject">The <c>sub</c> value that the key requires, or <see langword="null"/> for no check.</param>
	/// <returns><see cref="JwtValidationError.None"/> when all checks pass; otherwise, the first failed check.</returns>
	public static JwtValidationError CheckClaims(byte[] payload, DateTimeOffset now, JwtValidationOptions options, string? expectedSubject)
	{
		try
		{
			using var document = JsonDocument.Parse(payload);
			var root = document.RootElement;

			if (root.ValueKind != JsonValueKind.Object)
				return JwtValidationError.InvalidFormat;

			// Use milliseconds. NumericDate values can have a fraction (RFC 7519 section 2).
			var seconds = now.ToUnixTimeMilliseconds() / 1000d;
			var skew = options.ClockSkew.TotalSeconds;

			// RFC 7519 makes exp and nbf optional. Check each claim only when the token has it.
			if (root.TryGetProperty("exp", out var exp))
			{
				if (!TryGetNumericDate(exp, out var expiration))
					return JwtValidationError.InvalidFormat;

				if (seconds >= expiration + skew)
					return JwtValidationError.Expired;
			}
			else if (options.RequireExpiration)
			{
				return JwtValidationError.MissingExpiration;
			}

			if (root.TryGetProperty("nbf", out var nbf))
			{
				if (!TryGetNumericDate(nbf, out var notBefore))
					return JwtValidationError.InvalidFormat;

				if (seconds < notBefore - skew)
					return JwtValidationError.NotYetValid;
			}

			// Bind the key to one subject. A valid signature from member A does not authenticate member B.
			if (expectedSubject != null && !HasStringValue(root, "sub", expectedSubject))
				return JwtValidationError.SubjectMismatch;

			return JwtValidationError.None;
		}
		catch (JsonException)
		{
			return JwtValidationError.InvalidFormat;
		}
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
	/// Reads a string property of a JSON object.
	/// </summary>
	/// <param name="element">The JSON object.</param>
	/// <param name="name">The property name.</param>
	/// <returns>The string value, or <see langword="null"/> when the property is missing or is not a string.</returns>
	private static string? GetOptionalString(JsonElement element, string name) =>
		element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
			? value.GetString()
			: null;

	/// <summary>
	/// Checks that a JSON object has a string property with the expected value.
	/// </summary>
	/// <param name="element">The JSON object.</param>
	/// <param name="name">The property name.</param>
	/// <param name="expected">The expected string value.</param>
	/// <returns>True if the property is a string with the expected value; otherwise, false.</returns>
	private static bool HasStringValue(JsonElement element, string name, string expected) =>
		GetOptionalString(element, name) == expected;
}
