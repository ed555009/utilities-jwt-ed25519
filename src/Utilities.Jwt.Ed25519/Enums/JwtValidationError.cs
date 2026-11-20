namespace Utilities.Jwt.Ed25519.Enums;

/// <summary>
/// The reason why a token failed validation.
/// </summary>
/// <remarks>
/// WARNING: Do not return this value to the client. Use it for logs and tests only.
/// The value shows which key IDs exist.
/// </remarks>
public enum JwtValidationError
{
	/// <summary>
	/// The token is valid.
	/// </summary>
	None,

	/// <summary>
	/// The token is not 3 Base64 URL parts, or the payload is not a valid JSON object.
	/// </summary>
	InvalidFormat,

	/// <summary>
	/// The header is not valid: <c>alg</c> is not EdDSA, <c>typ</c> is not JWT, or the header has <c>crit</c>.
	/// </summary>
	InvalidHeader,

	/// <summary>
	/// The <c>kid</c> header is not a string, is longer than 128 characters, or has characters outside the allowed set.
	/// </summary>
	InvalidKeyId,

	/// <summary>
	/// The key resolver returned no key.
	/// </summary>
	KeyNotFound,

	/// <summary>
	/// The signature does not match the key.
	/// </summary>
	InvalidSignature,

	/// <summary>
	/// The <c>sub</c> claim does not match the expected subject of the key.
	/// </summary>
	SubjectMismatch,

	/// <summary>
	/// The current time is at or after <c>exp</c> plus the clock skew.
	/// </summary>
	Expired,

	/// <summary>
	/// The current time is before <c>nbf</c> minus the clock skew.
	/// </summary>
	NotYetValid,

	/// <summary>
	/// The token has no <c>exp</c> claim, and <see cref="Options.JwtValidationOptions.RequireExpiration"/> is true.
	/// </summary>
	MissingExpiration
}
