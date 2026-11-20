using Utilities.Jwt.Ed25519.Enums;

namespace Utilities.Jwt.Ed25519.Models;

/// <summary>
/// The result of a token validation.
/// </summary>
/// <typeparam name="T">The payload type.</typeparam>
/// <param name="IsValid">True if the token is valid; otherwise, false.</param>
/// <param name="Error">The reason for a failed validation, or <see cref="JwtValidationError.None"/>.</param>
/// <param name="Payload">The payload when the token is valid; otherwise, <see langword="null"/>.</param>
public sealed record JwtValidationResult<T>(bool IsValid, JwtValidationError Error, T? Payload)
{
	/// <summary>
	/// Creates the result of a valid token.
	/// </summary>
	/// <param name="payload">The payload of the token.</param>
	/// <returns>A valid result with the payload.</returns>
	public static JwtValidationResult<T> Success(T payload) => new(true, JwtValidationError.None, payload);

	/// <summary>
	/// Creates the result of a token that failed validation.
	/// </summary>
	/// <param name="error">The reason for the failure.</param>
	/// <returns>A failed result without a payload.</returns>
	public static JwtValidationResult<T> Failure(JwtValidationError error) => new(false, error, default);
}
