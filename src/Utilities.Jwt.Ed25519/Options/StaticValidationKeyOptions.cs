using System.ComponentModel.DataAnnotations;

namespace Utilities.Jwt.Ed25519.Options;

/// <summary>
/// Settings for the built-in resolver that validates with one fixed public key.
/// </summary>
public sealed class StaticValidationKeyOptions
{
	/// <summary>
	/// Gets or sets the Ed25519 public key in PEM format.
	/// </summary>
	[Required]
	public string PublicKeyPem { get; set; } = string.Empty;

	/// <summary>
	/// Gets or sets the key ID of the public key.
	/// When the value is set, the validator accepts only tokens with the same <c>kid</c>.
	/// When the value is <see langword="null"/>, the validator accepts tokens with any <c>kid</c> or no <c>kid</c>.
	/// </summary>
	public string? KeyId { get; set; }
}
