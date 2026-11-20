using System.ComponentModel.DataAnnotations;

namespace Utilities.Jwt.Ed25519.Options;

/// <summary>
/// Settings for the built-in resolver that signs with one fixed private key.
/// </summary>
/// <remarks>
/// WARNING: Read <see cref="PrivateKeyPem"/> from a secret store. Do not put it in appsettings.json.
/// Do not log this object.
/// </remarks>
public sealed class StaticSigningKeyOptions
{
	/// <summary>
	/// Gets or sets the Ed25519 private key in PEM format.
	/// </summary>
	[Required]
	public string PrivateKeyPem { get; set; } = string.Empty;

	/// <summary>
	/// Gets or sets the key ID that the signer writes to the <c>kid</c> header, or <see langword="null"/> for no <c>kid</c>.
	/// </summary>
	public string? KeyId { get; set; }
}
