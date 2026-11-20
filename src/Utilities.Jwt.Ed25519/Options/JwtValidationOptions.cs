using System;
using System.ComponentModel.DataAnnotations;

namespace Utilities.Jwt.Ed25519.Options;

/// <summary>
/// Settings for token validation.
/// </summary>
/// <remarks>
/// The defaults keep the validation behavior of version 8.0.1058.
/// </remarks>
public sealed class JwtValidationOptions
{
	/// <summary>
	/// Gets or sets the time that the validator adds to <c>exp</c> and removes from <c>nbf</c>.
	/// The value must be from 0 to 5 minutes. The default is 0.
	/// </summary>
	[Range(typeof(TimeSpan), "00:00:00", "00:05:00")]
	public TimeSpan ClockSkew { get; set; } = TimeSpan.Zero;

	/// <summary>
	/// Gets or sets a value that rejects a token without <c>exp</c>. The default is false.
	/// </summary>
	public bool RequireExpiration { get; set; }
}
