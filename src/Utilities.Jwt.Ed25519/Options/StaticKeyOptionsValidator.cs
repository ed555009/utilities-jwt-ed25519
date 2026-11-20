using System;
using System.Collections.Generic;
using Microsoft.Extensions.Options;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Options;

/// <summary>
/// Validates the PEM key and the key ID of the built-in fixed-key resolvers at startup.
/// </summary>
/// <remarks>
/// WARNING: The failure messages name the setting only. They never contain the PEM value.
/// </remarks>
internal sealed class StaticKeyOptionsValidator :
	IValidateOptions<StaticSigningKeyOptions>,
	IValidateOptions<StaticValidationKeyOptions>
{
	/// <inheritdoc />
	public ValidateOptionsResult Validate(string? name, StaticSigningKeyOptions options) =>
		ValidateKey(
			options.PrivateKeyPem,
			options.KeyId,
			nameof(StaticSigningKeyOptions.PrivateKeyPem),
			pem => Ed25519KeyLoader.LoadPrivateKey(pem));

	/// <inheritdoc />
	public ValidateOptionsResult Validate(string? name, StaticValidationKeyOptions options) =>
		ValidateKey(
			options.PublicKeyPem,
			options.KeyId,
			nameof(StaticValidationKeyOptions.PublicKeyPem),
			pem => Ed25519KeyLoader.LoadPublicKey(pem));

	/// <summary>
	/// Checks that the PEM value loads as the expected Ed25519 key and that the key ID has the key ID format.
	/// </summary>
	/// <param name="pem">The PEM value.</param>
	/// <param name="keyId">The key ID, or <see langword="null"/>.</param>
	/// <param name="pemSettingName">The name of the PEM setting for the failure message.</param>
	/// <param name="load">The method that loads the key.</param>
	/// <returns>The validation result.</returns>
	private static ValidateOptionsResult ValidateKey(string pem, string? keyId, string pemSettingName, Func<string, object> load)
	{
		var failures = new List<string>();

		if (keyId != null && !KeyIdFormat.IsValid(keyId))
			failures.Add($"KeyId must be 1 to {KeyIdFormat.MaxLength} characters from [A-Za-z0-9._:-].");

		// The DataAnnotations check reports an empty PEM value. Load only a value that is not empty.
		if (!string.IsNullOrEmpty(pem))
		{
			try
			{
				_ = load(pem);
			}
			catch (Exception)
			{
				// The PEM reader throws more than one exception type for bad input. Do not put the exception text in the message.
				failures.Add($"{pemSettingName} is not an Ed25519 key in PEM format.");
			}
		}

		return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
	}
}
