using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Utilities.Jwt.Ed25519.Models
{
	/// <summary>
	/// Represents the payload of a JSON Web Token (JWT).
	/// </summary>
	public class JwtPayload : BaseJwtPayload
	{
		private Dictionary<string, object>? _customClaims;

		/// <summary>
		/// Adds a custom claim to the JWT payload.
		/// </summary>
		/// <param name="key">The key of the custom claim.</param>
		/// <param name="value">The value of the custom claim.</param>
		public void AddClaim(string key, object value)
		{
			_customClaims ??= new Dictionary<string, object>();
			_customClaims[key] = value;
		}

		/// <summary>
		/// Exports the JWT payload as a JSON string.
		/// </summary>
		/// <returns>A JSON string representing the JWT payload.</returns>
		public string Export()
		{
			var payload = new Dictionary<string, object?>
			{
				{ "iss", Issuer },
				{ "sub", Subject },
				{ "aud", Audience },
				{ "exp", Expiration },
				{ "nbf", NotBefore },
				{ "iat", IssuedAt },
				{ "jti", JwtId }
			};

			_customClaims?.ToList().ForEach(claim => payload[claim.Key] = claim.Value);

			return JsonSerializer.Serialize(payload.Where(x => x.Value != null).ToDictionary(x => x.Key, x => x.Value));
		}
	}
}
