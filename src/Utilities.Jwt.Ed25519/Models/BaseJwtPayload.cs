using System.Text.Json.Serialization;
using Utilities.Jwt.Ed25519.Interfaces;

namespace Utilities.Jwt.Ed25519.Models
{
	/// <summary>
	/// Represents the base class for JWT payloads with RFC7519 registered claims.
	/// </summary>
	public abstract class BaseJwtPayload : IBaseJwtPayload
	{
		/// <summary>
		/// Gets or sets the issuer of the JWT.
		/// </summary>
		[JsonPropertyName("iss")]
		public string? Issuer { get; set; }

		/// <summary>
		/// Gets or sets the subject of the JWT.
		/// </summary>
		[JsonPropertyName("sub")]
		public string? Subject { get; set; }

		/// <summary>
		/// Gets or sets the audience of the JWT.
		/// </summary>
		[JsonPropertyName("aud")]
		public string? Audience { get; set; }

		/// <summary>
		/// Gets or sets the expiration time of the JWT as a Unix timestamp.
		/// </summary>
		[JsonPropertyName("exp")]
		public long? Expiration { get; set; }

		/// <summary>
		/// Gets or sets the "not before" time of the JWT as a Unix timestamp.
		/// </summary>
		[JsonPropertyName("nbf")]
		public long? NotBefore { get; set; }

		/// <summary>
		/// Gets or sets the issued at time of the JWT as a Unix timestamp.
		/// </summary>
		[JsonPropertyName("iat")]
		public long? IssuedAt { get; set; }

		/// <summary>
		/// Gets or sets the unique identifier for the JWT.
		/// </summary>
		[JsonPropertyName("jti")]
		public string? JwtId { get; set; }
	}
}
